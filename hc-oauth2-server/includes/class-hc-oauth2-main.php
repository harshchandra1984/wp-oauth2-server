<?php
/**
 * Main OAuth2 Server Class
 *
 * This class handles the core OAuth2 server functionality including:
 * - Request routing for OAuth2 endpoints
 * - Database table creation
 * - Client validation
 * - Token generation utilities
 *
 * @package HC_OAuth2_Server
 * @since 1.0.0
 */
if (!defined('ABSPATH')) {
    exit;
}

class HC_OAuth2_Server {
    
    /**
     * Auth handler instance.
     *
     * @since 1.0.0
     * @var HC_OAuth2_Auth_Handler
     */
    private $auth_handler;
    
    /**
     * Initialize the plugin hooks and actions.
     *
     * Sets up all WordPress hooks for OAuth2 endpoints including:
     * - Authorization endpoint
     * - Token endpoint
     * - Userinfo endpoint
     * - Logout endpoint
     *
     * @since 1.0.0
     * @return void
     */
    public function init() {
        // Initialize auth handler early to register session and login hooks
        $this->auth_handler = new HC_OAuth2_Auth_Handler();
        
        add_action('init', array($this, 'handle_oauth2_requests'));
        add_action('wp_ajax_nopriv_oauth2_authorize', array($this, 'handle_authorization'));
        add_action('wp_ajax_oauth2_authorize', array($this, 'handle_authorization'));
        add_action('wp_ajax_nopriv_oauth2_token', array($this, 'handle_token_request'));
        add_action('wp_ajax_oauth2_token', array($this, 'handle_token_request'));
        add_action('wp_ajax_nopriv_oauth2_userinfo', array($this, 'handle_userinfo_request'));
        add_action('wp_ajax_oauth2_userinfo', array($this, 'handle_userinfo_request'));
        add_action('wp_ajax_nopriv_oauth2_logout', array($this, 'handle_logout_request'));
        add_action('wp_ajax_oauth2_logout', array($this, 'handle_logout_request'));
    }
    
    /**
     * Handle OAuth2 requests by routing to appropriate handlers.
     *
     * Intercepts requests to OAuth2 endpoints and routes them to the
     * appropriate handler methods. Supports both REST-style URLs and
     * AJAX endpoints.
     *
     * @since 1.0.0
     * @return void
     */
    public function handle_oauth2_requests() {
        $request_uri = isset($_SERVER['REQUEST_URI']) ? esc_url_raw(wp_unslash($_SERVER['REQUEST_URI'])) : '';
        
        if (strpos($request_uri, '/oauth2/authorize') !== false) {
            $this->handle_authorization();
            exit;
        }
        
        if (strpos($request_uri, '/oauth2/token') !== false) {
            $this->handle_token_request();
            exit;
        }
        
        if (strpos($request_uri, '/oauth2/userinfo') !== false) {
            $this->handle_userinfo_request();
            exit;
        }
        
        if (strpos($request_uri, '/oauth2/logout') !== false) {
            $this->handle_logout_request();
            exit;
        }
    }
    
    /**
     * Handle authorization request.
     *
     * Delegates to the auth handler to process OAuth2 authorization requests.
     * This endpoint initiates the authorization code flow.
     *
     * @since 1.0.0
     * @return void
     */
    public function handle_authorization() {
        $this->auth_handler->handle_authorization();
    }
    
    /**
     * Handle token request.
     *
     * Delegates to the auth handler to process OAuth2 token requests.
     * Supports both authorization code and refresh token grant types.
     *
     * @since 1.0.0
     * @return void
     */
    public function handle_token_request() {
        $this->auth_handler->handle_token_request();
    }
    
    /**
     * Handle userinfo request.
     *
     * Delegates to the auth handler to process OAuth2 userinfo requests.
     * Returns user information for authenticated requests.
     *
     * @since 1.0.0
     * @return void
     */
    public function handle_userinfo_request() {
        $this->auth_handler->handle_userinfo_request();
    }
    
    /**
     * Handle logout request.
     *
     * Delegates to the auth handler to process OAuth2 logout requests.
     * Implements RP-Initiated Logout (RPLO) functionality.
     *
     * @since 1.0.0
     * @return void
     */
    public function handle_logout_request() {
        $this->auth_handler->handle_logout_request();
    }
    
    /**
     * Create necessary database tables for OAuth2 functionality.
     *
     * Creates three tables:
     * - oauth2_clients: Stores registered OAuth2 client applications
     * - oauth2_codes: Stores temporary authorization codes
     * - oauth2_tokens: Stores access and refresh tokens
     *
     * Uses WordPress dbDelta() function to ensure tables are created
     * or updated correctly.
     *
     * @since 1.0.0
     * @return void
     */
    public static function create_tables() {
        global $wpdb;
        
        /**
         * Fires before creating OAuth2 database tables.
         *
         * @since 1.0.0
         */
        do_action('hc_oauth2_before_create_tables');
        
        $charset_collate = $wpdb->get_charset_collate();
        
        // OAuth2 clients table
        $clients_table = $wpdb->prefix . 'oauth2_clients';
        $sql_clients = "CREATE TABLE $clients_table (
            id mediumint(9) NOT NULL AUTO_INCREMENT,
            client_id varchar(255) NOT NULL,
            client_secret varchar(255) NOT NULL,
            redirect_uri text NOT NULL,
            name varchar(255) NOT NULL,
            created_at datetime DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            UNIQUE KEY client_id (client_id),
            KEY created_at (created_at)
        ) $charset_collate;";
        
        // OAuth2 authorization codes table
        $codes_table = $wpdb->prefix . 'oauth2_codes';
        $sql_codes = "CREATE TABLE $codes_table (
            id mediumint(9) NOT NULL AUTO_INCREMENT,
            code varchar(255) NOT NULL,
            client_id varchar(255) NOT NULL,
            user_id bigint(20) NOT NULL,
            redirect_uri text NOT NULL,
            scope text,
            expires_at datetime NOT NULL,
            created_at datetime DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            UNIQUE KEY code (code),
            KEY client_id (client_id),
            KEY expires_at (expires_at),
            KEY user_id (user_id)
        ) $charset_collate;";
        
        // OAuth2 access tokens table
        $tokens_table = $wpdb->prefix . 'oauth2_tokens';
        $sql_tokens = "CREATE TABLE $tokens_table (
            id mediumint(9) NOT NULL AUTO_INCREMENT,
            access_token varchar(255) NOT NULL,
            refresh_token varchar(255),
            client_id varchar(255) NOT NULL,
            user_id bigint(20) NOT NULL,
            scope text,
            expires_at datetime NOT NULL,
            created_at datetime DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            UNIQUE KEY access_token (access_token),
            UNIQUE KEY refresh_token (refresh_token),
            KEY client_id (client_id),
            KEY user_id (user_id),
            KEY expires_at (expires_at)
        ) $charset_collate;";
        
        require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
        dbDelta($sql_clients);
        dbDelta($sql_codes);
        dbDelta($sql_tokens);
        
        /**
         * Fires after OAuth2 database tables are created.
         *
         * @since 1.0.0
         */
        do_action('hc_oauth2_after_create_tables');
    }
    
    /**
     * Generate a cryptographically secure random string.
     *
     * Uses PHP's random_bytes() function to generate secure random bytes,
     * then converts them to hexadecimal string format.
     *
     * @since 1.0.0
     * @param int $length The desired length of the output string. Default 32.
     * @return string A hexadecimal random string of the specified length.
     */
    public static function generate_random_string($length = 32) {
        // Ensure minimum length of 32 characters
        $length = max(32, absint($length));
        // Generate secure random bytes and convert to hex
        return bin2hex(random_bytes((int) ceil($length / 2)));
    }
    
    /**
     * Validate OAuth2 client credentials.
     *
     * Checks if a client_id exists in the database and optionally
     * validates the client_secret if provided.
     *
     * @since 1.0.0
     * @param string      $client_id     The OAuth2 client ID to validate.
     * @param string|null $client_secret Optional. The client secret to validate.
     * @return object|false The client object if valid, false otherwise.
     */
    public static function validate_client($client_id, $client_secret = null) {
        global $wpdb;
        
        $clients_table = $wpdb->prefix . 'oauth2_clients';
        
        if ($client_secret) {
            // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
            $client = $wpdb->get_row($wpdb->prepare(
                "SELECT * FROM $clients_table WHERE client_id = %s AND client_secret = %s",
                $client_id,
                $client_secret
            ));
        } else {
            // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
            $client = $wpdb->get_row($wpdb->prepare(
                "SELECT * FROM $clients_table WHERE client_id = %s",
                $client_id
            ));
        }
        
        /**
         * Filter the validated client object.
         *
         * @since 1.0.0
         * @param object|false $client       The client object or false if not found.
         * @param string       $client_id    The client ID.
         * @param string|null  $client_secret The client secret (null if not provided).
         */
        return apply_filters('hc_oauth2_validate_client', $client, $client_id, $client_secret);
    }
    
    /**
     * Validate redirect URI against registered client URIs.
     *
     * Checks if the provided redirect_uri matches one of the registered
     * redirect URIs for the given client. Supports multiple redirect URIs
     * separated by commas.
     *
     * @since 1.0.0
     * @param string $client_id   The OAuth2 client ID.
     * @param string $redirect_uri The redirect URI to validate.
     * @return bool True if the redirect URI is valid, false otherwise.
     */
    public static function validate_redirect_uri($client_id, $redirect_uri) {
        global $wpdb;
        
        $clients_table = $wpdb->prefix . 'oauth2_clients';
        
        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
        $client = $wpdb->get_row($wpdb->prepare(
            "SELECT redirect_uri FROM $clients_table WHERE client_id = %s",
            $client_id
        ));
        
        if (!$client) {
            return false;
        }
        
        $allowed_uris = explode(',', $client->redirect_uri);
        $allowed_uris = array_map('trim', $allowed_uris);
        
        $is_valid = in_array($redirect_uri, $allowed_uris, true);
        
        /**
         * Filter the redirect URI validation result.
         *
         * @since 1.0.0
         * @param bool   $is_valid    Whether the redirect URI is valid.
         * @param string $client_id   The client ID.
         * @param string $redirect_uri The redirect URI being validated.
         * @param array  $allowed_uris Array of allowed redirect URIs.
         */
        return apply_filters('hc_oauth2_validate_redirect_uri', $is_valid, $client_id, $redirect_uri, $allowed_uris);
    }
} 