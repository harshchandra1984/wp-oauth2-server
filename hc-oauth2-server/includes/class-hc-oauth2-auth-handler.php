<?php
/**
 * OAuth2 Authentication Handler
 *
 * Handles all OAuth2 authentication and authorization flows including:
 * - Authorization code generation and validation
 * - Access token generation and validation
 * - Refresh token handling
 * - User information retrieval
 * - RP-Initiated Logout (RPLO)
 * - Session management for OAuth2 flows
 * - Integration with WordPress and WooCommerce login systems
 *
 * @package HC_OAuth2_Server
 * @since 1.0.0
 */
if (!defined('ABSPATH')) {
    exit;
}

class HC_OAuth2_Auth_Handler {
    
    /**
     * Constructor - Initialize OAuth2 authentication hooks.
     *
     * Sets up WordPress hooks for session management, login redirects,
     * and WooCommerce integration.
     *
     * @since 1.0.0
     */
    public function __construct() {
       
        add_action('init', array($this, 'ensure_session_started'), 1);  // Start session early to ensure it works across all pages
        add_filter('login_redirect', array($this, 'handle_oauth2_login_redirect'), 10, 3); // Hook into login redirect to handle OAuth2 flow after login
        add_filter('woocommerce_login_redirect', array($this, 'handle_woocommerce_oauth2_login_redirect'), 100, 2);  // Hook into WooCommerce login redirect with higher priority
    }
    
    /**
     * Ensure PHP session is started early in the request lifecycle.
     *
     * Required for storing OAuth2 parameters during the authorization flow.
     * Called on the 'init' hook with priority 1 to start before other plugins.
     *
     * @since 1.0.0
     * @return void
     */
    public function ensure_session_started() {
        if (!session_id()) {
            // Configure secure session parameters
            ini_set('session.cookie_httponly', 1);
            if (is_ssl()) {
                ini_set('session.cookie_secure', 1);
            }
            ini_set('session.use_only_cookies', 1);
            ini_set('session.cookie_samesite', 'Strict');
            
            session_start();
            
            // Regenerate session ID periodically to prevent session fixation
            if (!isset($_SESSION['hc_oauth2_session_init'])) {
                session_regenerate_id(true);
                $_SESSION['hc_oauth2_session_init'] = true;
            }
        }
    }
    
    /**
     * Handle OAuth2 authorization request.
     *
     * Processes the authorization endpoint request according to OAuth2 spec.
     * Validates client, redirect URI, and response type. If user is not logged in,
     * stores OAuth2 parameters in session and redirects to login. If logged in,
     * generates and returns authorization code.
     *
     * @since 1.0.0
     * @return void
     */
    public function handle_authorization() {
        // Rate limiting check
        if (!$this->check_rate_limit('authorization_request')) {
            wp_die(esc_html__('Rate limit exceeded. Please try again later.', 'hc-oauth2-server'), esc_html__('Rate Limit Exceeded', 'hc-oauth2-server'), array('response' => 429));
            return;
        }
        
        $response_type = isset($_GET['response_type']) ? sanitize_text_field($_GET['response_type']) : '';
        $client_id = isset($_GET['client_id']) ? sanitize_text_field($_GET['client_id']) : '';
        $redirect_uri = isset($_GET['redirect_uri']) ? esc_url_raw($_GET['redirect_uri']) : '';
        $scope = isset($_GET['scope']) ? sanitize_text_field($_GET['scope']) : '';
        $state = isset($_GET['state']) ? sanitize_text_field($_GET['state']) : '';
        
        /**
         * Fires before processing OAuth2 authorization request.
         *
         * @since 1.0.0
         * @param string $response_type The response type requested.
         * @param string $client_id     The client ID.
         * @param string $redirect_uri  The redirect URI.
         * @param string $scope         The requested scope.
         * @param string $state         The state parameter.
         */
        do_action('hc_oauth2_before_authorize', $response_type, $client_id, $redirect_uri, $scope, $state);
        
        // Validate required parameters
        if (empty($response_type) || empty($client_id) || empty($redirect_uri)) {
            $this->oauth_error('invalid_request', __('Missing required parameters', 'hc-oauth2-server'), $redirect_uri, $state);
            return;
        }
        
        // Validate response type
        if ($response_type !== 'code') {
            $this->oauth_error('unsupported_response_type', __('Only authorization code flow is supported', 'hc-oauth2-server'), $redirect_uri, $state);
            return;
        }
        
        // Validate client
        $client = HC_OAuth2_Server::validate_client($client_id);
        if (!$client) {
            $this->oauth_error('unauthorized_client', __('Invalid client', 'hc-oauth2-server'), $redirect_uri, $state);
            return;
        }
        
        // Validate redirect URI
        if (!HC_OAuth2_Server::validate_redirect_uri($client_id, $redirect_uri)) {
            $this->oauth_error('invalid_request', __('Invalid redirect URI', 'hc-oauth2-server'), $redirect_uri, $state);
            return;
        }
        
        // Check if user is logged in
        if (!is_user_logged_in()) {
            // Store OAuth2 parameters in session and redirect to login
            $this->store_oauth_params($client_id, $redirect_uri, $scope, $state);
            // Redirect to WooCommerce My Account page instead of default WordPress login
            $login_url = function_exists('wc_get_page_permalink') ? wc_get_page_permalink('myaccount') : wp_login_url();
            /**
             * Filter the login URL for OAuth2 authorization flow.
             *
             * @since 1.0.0
             * @param string $login_url   The login URL.
             * @param string $client_id   The client ID.
             * @param string $redirect_uri The redirect URI.
             */
            $login_url = apply_filters('hc_oauth2_login_url', $login_url, $client_id, $redirect_uri);
            wp_safe_redirect($login_url);
            exit;
        }
        
        // User is logged in, generate authorization code
        $this->generate_authorization_code($client_id, $redirect_uri, $scope, $state);
    }
    
    /**
     * Handle OAuth2 token request.
     *
     * Processes token endpoint requests. Validates client credentials and
     * routes to appropriate grant type handler (authorization_code or refresh_token).
     *
     * @since 1.0.0
     * @return void
     */
    public function handle_token_request() {
        // Rate limiting check
        if (!$this->check_rate_limit('token_request')) {
            $this->token_error('invalid_request', __('Rate limit exceeded. Please try again later.', 'hc-oauth2-server'));
            return;
        }
        
        $grant_type = isset($_POST['grant_type']) ? sanitize_text_field($_POST['grant_type']) : '';
        $client_id = isset($_POST['client_id']) ? sanitize_text_field($_POST['client_id']) : '';
        $client_secret = isset($_POST['client_secret']) ? sanitize_text_field($_POST['client_secret']) : '';
        
        // Validate client credentials
        $client = HC_OAuth2_Server::validate_client($client_id, $client_secret);
        if (!$client) {
            // Log failed authentication attempt for security monitoring
            $this->log_failed_auth_attempt('token_request', $client_id);
            $this->token_error('invalid_client', __('Invalid client credentials', 'hc-oauth2-server'));
            return;
        }
        
        switch ($grant_type) {
            case 'authorization_code':
                $this->handle_authorization_code_grant($client);
                break;
            case 'refresh_token':
                $this->handle_refresh_token_grant($client);
                break;
            default:
                $this->token_error('unsupported_grant_type', __('Unsupported grant type', 'hc-oauth2-server'));
                break;
        }
    }
    
    /**
     * Handle authorization code grant type.
     *
     * Validates the authorization code, generates access and refresh tokens,
     * and deletes the used authorization code.
     *
     * @since 1.0.0
     * @param object $client The validated OAuth2 client object.
     * @return void
     */
    private function handle_authorization_code_grant($client) {
        $code = isset($_POST['code']) ? sanitize_text_field($_POST['code']) : '';
        $redirect_uri = isset($_POST['redirect_uri']) ? esc_url_raw($_POST['redirect_uri']) : '';
        
        if (empty($code) || empty($redirect_uri)) {
            $this->token_error('invalid_request', __('Missing required parameters', 'hc-oauth2-server'));
            return;
        }
        
        // Validate authorization code
        $auth_code = $this->validate_authorization_code($code, $client->client_id, $redirect_uri);
        if (!$auth_code) {
            $this->token_error('invalid_grant', __('Invalid authorization code', 'hc-oauth2-server'));
            return;
        }
        
        /**
         * Fires before issuing access token from authorization code.
         *
         * @since 1.0.0
         * @param object $auth_code The authorization code object.
         * @param object $client    The client object.
         */
        do_action('hc_oauth2_before_token_issue', $auth_code, $client);
        
        // Generate access token
        $token_data = $this->generate_access_token($auth_code->user_id, $client->client_id, $auth_code->scope);
        
        if ($token_data) {
            /**
             * Filter the token data before returning to client.
             *
             * @since 1.0.0
             * @param array  $token_data The token data array.
             * @param object $auth_code  The authorization code object.
             * @param object $client     The client object.
             */
            $token_data = apply_filters('hc_oauth2_token_data', $token_data, $auth_code, $client);
            
            /**
             * Fires after access token is successfully issued.
             *
             * @since 1.0.0
             * @param array  $token_data The token data array.
             * @param object $auth_code  The authorization code object.
             * @param object $client     The client object.
             */
            do_action('hc_oauth2_after_token_issue', $token_data, $auth_code, $client);
            
            // Delete used authorization code
            $this->delete_authorization_code($code);
            
            // Return token response
            $this->token_success($token_data);
        } else {
            $this->token_error('server_error', __('Failed to generate access token', 'hc-oauth2-server'));
        }
    }
    
    /**
     * Handle refresh token grant type.
     *
     * Validates the refresh token, generates new access and refresh tokens,
     * and deletes the old access token.
     *
     * @since 1.0.0
     * @param object $client The validated OAuth2 client object.
     * @return void
     */
    private function handle_refresh_token_grant($client) {
        $refresh_token = isset($_POST['refresh_token']) ? sanitize_text_field($_POST['refresh_token']) : '';
        
        if (empty($refresh_token)) {
            $this->token_error('invalid_request', __('Missing refresh token', 'hc-oauth2-server'));
            return;
        }
        
        // Validate refresh token
        $token = $this->validate_refresh_token($refresh_token, $client->client_id);
        if (!$token) {
            $this->token_error('invalid_grant', __('Invalid refresh token', 'hc-oauth2-server'));
            return;
        }
        
        /**
         * Fires before refreshing access token.
         *
         * @since 1.0.0
         * @param object $token  The refresh token object.
         * @param object $client The client object.
         */
        do_action('hc_oauth2_before_token_refresh', $token, $client);
        
        // Generate new access token
        $token_data = $this->generate_access_token($token->user_id, $client->client_id, $token->scope);
        
        if ($token_data) {
            /**
             * Filter the refreshed token data before returning to client.
             *
             * @since 1.0.0
             * @param array  $token_data The new token data array.
             * @param object $old_token  The old token object.
             * @param object $client     The client object.
             */
            $token_data = apply_filters('hc_oauth2_refresh_token_data', $token_data, $token, $client);
            
            /**
             * Fires after access token is successfully refreshed.
             *
             * @since 1.0.0
             * @param array  $token_data The new token data array.
             * @param object $old_token  The old token object.
             * @param object $client     The client object.
             */
            do_action('hc_oauth2_after_token_refresh', $token_data, $token, $client);
            
            // Delete old token
            $this->delete_access_token($token->access_token);
            
            // Return token response
            $this->token_success($token_data);
        } else {
            $this->token_error('server_error', __('Failed to generate access token', 'hc-oauth2-server'));
        }
    }
    
    /**
     * Handle OAuth2 userinfo request.
     *
     * Validates the access token and returns user information including
     * user ID, email, name, registration date, and roles.
     *
     * @since 1.0.0
     * @return void
     */
    public function handle_userinfo_request() {
        // Rate limiting check
        if (!$this->check_rate_limit('userinfo_request')) {
            $this->userinfo_error('invalid_request', __('Rate limit exceeded. Please try again later.', 'hc-oauth2-server'));
            return;
        }
        
        $access_token = $this->get_access_token_from_header();
        
        if (!$access_token) {
            $this->userinfo_error('invalid_token', __('Missing access token', 'hc-oauth2-server'));
            return;
        }
        
        // Validate access token
        $token = $this->validate_access_token($access_token);
        if (!$token) {
            $this->userinfo_error('invalid_token', __('Invalid access token', 'hc-oauth2-server'));
            return;
        }
        
        // Get user information from wp_users table
        $user_info = $this->get_user_info($token->user_id);
        if (!$user_info) {
            $this->userinfo_error('invalid_token', __('User not found', 'hc-oauth2-server'));
            return;
        }
        
        /**
         * Filter the user information returned by the userinfo endpoint.
         *
         * @since 1.0.0
         * @param array  $user_info The user information array.
         * @param object $token     The token object.
         */
        $user_info = apply_filters('hc_oauth2_userinfo_data', $user_info, $token);
        
        /**
         * Fires before returning user information.
         *
         * @since 1.0.0
         * @param array  $user_info The user information array.
         * @param object $token     The token object.
         */
        do_action('hc_oauth2_before_userinfo', $user_info, $token);
        
        // Return user information
        $this->userinfo_success($user_info);
    }
    
    /**
     * Handle OAuth2 logout request (RP-Initiated Logout).
     *
     * Implements RP-Initiated Logout (RPLO) as per OAuth2 specifications.
     * Supports both GET and POST methods. Revokes all tokens for the user
     * and optionally redirects to a post-logout URI.
     *
     * @since 1.0.0
     * @return void
     */
    public function handle_logout_request() {
        // Get access token from header or parameter
        $access_token = $this->get_access_token_from_header();
        if (!$access_token) {
            $access_token = isset($_REQUEST['access_token']) ? sanitize_text_field($_REQUEST['access_token']) : '';
        }
        
        // Get optional parameters
        $client_id = isset($_REQUEST['client_id']) ? sanitize_text_field($_REQUEST['client_id']) : '';
        $post_logout_redirect_uri = isset($_REQUEST['post_logout_redirect_uri']) ? esc_url_raw($_REQUEST['post_logout_redirect_uri']) : '';
        $state = isset($_REQUEST['state']) ? sanitize_text_field($_REQUEST['state']) : '';
        
        $user_id = null;
        $token_client_id = null;
        
        // If access token is provided, validate it and get user info
        if (!empty($access_token)) {
            $token = $this->validate_access_token($access_token);
            if ($token) {
                $user_id = $token->user_id;
                $token_client_id = $token->client_id;
                
                // Validate client_id if provided
                if (!empty($client_id) && $client_id !== $token_client_id) {
                    $this->logout_error('invalid_request', __('Client ID mismatch', 'hc-oauth2-server'));
                    return;
                }
                
                // Use token's client_id if not provided
                if (empty($client_id)) {
                    $client_id = $token_client_id;
                }
            }
        }
        
        // If no valid token but user is logged in, use current user
        if (!$user_id && is_user_logged_in()) {
            $user_id = get_current_user_id();
        }
        
        /**
         * Fires before revoking tokens during logout.
         *
         * @since 1.0.0
         * @param int    $user_id   The user ID.
         * @param string $client_id The client ID (may be empty).
         */
        do_action('hc_oauth2_before_token_revoke', $user_id, $client_id);
        
        // Revoke all tokens for this user and client
        if ($user_id) {
            if ($client_id) {
                // Revoke tokens for specific client
                $this->revoke_user_client_tokens($user_id, $client_id);
            } else {
                // Revoke all tokens for user
                $this->revoke_all_user_tokens($user_id);
            }
        }
        
        /**
         * Fires after tokens are revoked during logout.
         *
         * @since 1.0.0
         * @param int    $user_id   The user ID.
         * @param string $client_id The client ID (may be empty).
         */
        do_action('hc_oauth2_after_token_revoke', $user_id, $client_id);
        
        // Log out the WordPress user
        wp_logout();
        
        // Handle redirect or JSON response
        if (!empty($post_logout_redirect_uri)) {
            // Validate redirect URI if client_id is known
            if ($client_id && !HC_OAuth2_Server::validate_redirect_uri($client_id, $post_logout_redirect_uri)) {
                $this->logout_error('invalid_request', __('Invalid post_logout_redirect_uri', 'hc-oauth2-server'));
                return;
            }
            
            // Redirect to post logout URI
            $redirect_url = $post_logout_redirect_uri;
            if (!empty($state)) {
                $redirect_url = add_query_arg('state', $state, $redirect_url);
            }
            
            wp_safe_redirect($redirect_url);
            exit;
        } else {
            // Return JSON success response
            $this->logout_success();
        }
    }
    
    /**
     * Store OAuth2 parameters in PHP session.
     *
     * Stores OAuth2 authorization parameters in session to be retrieved
     * after user login completes.
     *
     * @since 1.0.0
     * @param string $client_id   The OAuth2 client ID.
     * @param string $redirect_uri The redirect URI.
     * @param string $scope       The requested scope.
     * @param string $state       The state parameter.
     * @return void
     */
    private function store_oauth_params($client_id, $redirect_uri, $scope, $state) {
        if (!session_id()) {
            session_start();
        }
        
        $_SESSION['hc_oauth2_server_params'] = array(
            'client_id' => $client_id,
            'redirect_uri' => $redirect_uri,
            'scope' => $scope,
            'state' => $state
        );
    }
    
    /**
     * Get stored OAuth2 parameters from session.
     *
     * Retrieves OAuth2 parameters that were stored before redirecting to login.
     *
     * @since 1.0.0
     * @return array|null The stored OAuth2 parameters or null if not found.
     */
    private function get_stored_oauth_params() {
        if (!session_id()) {
            session_start();
        }
        
        return isset($_SESSION['hc_oauth2_server_params']) ? $_SESSION['hc_oauth2_server_params'] : null;
    }
    
    /**
     * Clear stored OAuth2 parameters from session.
     *
     * Removes OAuth2 parameters from session after they've been used.
     *
     * @since 1.0.0
     * @return void
     */
    private function clear_stored_oauth_params() {
        if (!session_id()) {
            session_start();
        }
        
        if (isset($_SESSION['hc_oauth2_server_params'])) {
            unset($_SESSION['hc_oauth2_server_params']);
        }
    }
    
    /**
     * Generate and store an OAuth2 authorization code.
     *
     * Creates a cryptographically secure authorization code, stores it in the database
     * with expiration time (10 minutes), and redirects back to the client with the code.
     *
     * @since 1.0.0
     * @param string $client_id   The OAuth2 client ID.
     * @param string $redirect_uri The redirect URI.
     * @param string $scope       The requested scope.
     * @param string $state       The state parameter.
     * @return void
     */
    private function generate_authorization_code($client_id, $redirect_uri, $scope, $state) {
        global $wpdb;
        
        $user_id = get_current_user_id();
        // Generate longer code for better security (64 characters)
        $code = HC_OAuth2_Server::generate_random_string(64);
        
        /**
         * Filter the authorization code expiration time in seconds.
         *
         * @since 1.0.0
         * @param int    $expires_in Expiration time in seconds. Default 600 (10 minutes).
         * @param string $client_id  The client ID.
         * @param int    $user_id    The user ID.
         */
        $expires_in = apply_filters('hc_oauth2_authorization_code_expires_in', 600, $client_id, $user_id);
        $expires_at = gmdate('Y-m-d H:i:s', strtotime('+' . $expires_in . ' seconds'));
        
        $codes_table = $wpdb->prefix . 'oauth2_codes';
        
        $result = $wpdb->insert(
            $codes_table,
            array(
                'code' => $code,
                'client_id' => $client_id,
                'user_id' => $user_id,
                'redirect_uri' => $redirect_uri,
                'scope' => $scope,
                'expires_at' => $expires_at
            ),
            array('%s', '%s', '%d', '%s', '%s', '%s')
        );
        
        if ($result === false) {
            $this->oauth_error('server_error', __('Failed to generate authorization code', 'hc-oauth2-server'), $redirect_uri, $state);
            return;
        }
        
        /**
         * Fires after authorization code is successfully generated.
         *
         * @since 1.0.0
         * @param string $code       The authorization code.
         * @param string $client_id  The client ID.
         * @param int    $user_id    The user ID.
         * @param string $redirect_uri The redirect URI.
         * @param string $scope      The requested scope.
         */
        do_action('hc_oauth2_after_authorize', $code, $client_id, $user_id, $redirect_uri, $scope);
        
        // Redirect back to client with authorization code
        $redirect_url = add_query_arg(array(
            'code' => $code,
            'state' => $state
        ), $redirect_uri);
        
        /**
         * Filter the redirect URL after authorization.
         *
         * @since 1.0.0
         * @param string $redirect_url The redirect URL.
         * @param string $code         The authorization code.
         * @param string $state        The state parameter.
         * @param string $redirect_uri The original redirect URI.
         */
        $redirect_url = apply_filters('hc_oauth2_authorization_redirect_url', $redirect_url, $code, $state, $redirect_uri);
        
        wp_safe_redirect($redirect_url);
        exit;
    }
    
    /**
     * Validate an OAuth2 authorization code.
     *
     * Checks if the authorization code exists, is not expired, and matches
     * the client_id and redirect_uri.
     *
     * @since 1.0.0
     * @param string $code        The authorization code to validate.
     * @param string $client_id   The OAuth2 client ID.
     * @param string $redirect_uri The redirect URI.
     * @return object|false The authorization code object if valid, false otherwise.
     */
    private function validate_authorization_code($code, $client_id, $redirect_uri) {
        global $wpdb;
        
        $codes_table = $wpdb->prefix . 'oauth2_codes';
        $timeNow = gmdate('Y-m-d H:i:s');
        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
        $auth_code = $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM $codes_table WHERE code = %s AND client_id = %s AND redirect_uri = %s AND expires_at > %s",
            $code,
            $client_id,
            $redirect_uri,
            $timeNow
        ));
        
        return $auth_code;
    }
    
    /**
     * Generate OAuth2 access and refresh tokens.
     *
     * Creates cryptographically secure access and refresh tokens, stores them
     * in the database with expiration time (1 hour), and returns token data.
     *
     * @since 1.0.0
     * @param int    $user_id   The WordPress user ID.
     * @param string $client_id The OAuth2 client ID.
     * @param string $scope     The requested scope.
     * @return array|false Token data array on success, false on failure.
     */
    private function generate_access_token($user_id, $client_id, $scope) {
        global $wpdb;
        
        // Generate longer tokens for better security (64 characters)
        $access_token = HC_OAuth2_Server::generate_random_string(64);
        $refresh_token = HC_OAuth2_Server::generate_random_string(64);
        
        /**
         * Filter the access token expiration time in seconds.
         *
         * @since 1.0.0
         * @param int    $expires_in Expiration time in seconds. Default 3600 (1 hour).
         * @param int    $user_id    The user ID.
         * @param string $client_id  The client ID.
         * @param string $scope      The requested scope.
         */
        $expires_in = apply_filters('hc_oauth2_token_expires_in', 3600, $user_id, $client_id, $scope);
        $expires_at = gmdate('Y-m-d H:i:s', strtotime('+' . $expires_in . ' seconds'));
        
        $tokens_table = $wpdb->prefix . 'oauth2_tokens';
        
        $result = $wpdb->insert(
            $tokens_table,
            array(
                'access_token' => $access_token,
                'refresh_token' => $refresh_token,
                'client_id' => $client_id,
                'user_id' => $user_id,
                'scope' => $scope,
                'expires_at' => $expires_at
            ),
            array('%s', '%s', '%s', '%d', '%s', '%s')
        );
        
        if ($result === false) {
            return false;
        }
        
        $token_data = array(
            'access_token' => $access_token,
            'token_type' => 'Bearer',
            'expires_in' => $expires_in,
            'refresh_token' => $refresh_token,
            'scope' => $scope
        );
        
        /**
         * Filter the access token data before storing in database.
         *
         * @since 1.0.0
         * @param array  $token_data The token data array.
         * @param int    $user_id    The user ID.
         * @param string $client_id  The client ID.
         * @param string $scope      The requested scope.
         */
        return apply_filters('hc_oauth2_access_token_data', $token_data, $user_id, $client_id, $scope);
    }
    
    /**
     * Validate an OAuth2 access token.
     *
     * Checks if the access token exists in the database and is not expired.
     *
     * @since 1.0.0
     * @param string $access_token The access token to validate.
     * @return object|false The token object if valid, false otherwise.
     */
    private function validate_access_token($access_token) {
        global $wpdb;
        
        $tokens_table = $wpdb->prefix . 'oauth2_tokens';
        $timeNow = gmdate('Y-m-d H:i:s');
        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
        $token = $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM $tokens_table WHERE access_token = %s AND expires_at > %s",
            $access_token,
            $timeNow
        ));
        
        return $token;
    }
    
    /**
     * Validate an OAuth2 refresh token.
     *
     * Checks if the refresh token exists in the database and matches the client_id.
     *
     * @since 1.0.0
     * @param string $refresh_token The refresh token to validate.
     * @param string $client_id     The OAuth2 client ID.
     * @return object|false The token object if valid, false otherwise.
     */
    private function validate_refresh_token($refresh_token, $client_id) {
        global $wpdb;
        
        $tokens_table = $wpdb->prefix . 'oauth2_tokens';
        
        $token = $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM $tokens_table WHERE refresh_token = %s AND client_id = %s",
            $refresh_token,
            $client_id
        ));
        
        return $token;
    }
    
    /**
     * Get user information from WordPress database.
     *
     * Retrieves user data including ID, email, registration date, first name,
     * last name, and roles from WordPress users and usermeta tables.
     *
     * @since 1.0.0
     * @param int $user_id The WordPress user ID.
     * @return array|false User information array on success, false on failure.
     */
    private function get_user_info($user_id) {
        global $wpdb;
        
        $users_table = $wpdb->prefix . 'users';
        $usermeta_table = $wpdb->prefix . 'usermeta';
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
        $user = $wpdb->get_row($wpdb->prepare(
                    "SELECT u.ID AS legacy_id, u.user_email, u.user_registered,
                    MAX(CASE WHEN um.meta_key = 'first_name' THEN um.meta_value END) AS first_name,
                    MAX(CASE WHEN um.meta_key = 'last_name' THEN um.meta_value END) AS last_name,
                    MAX(CASE WHEN um.meta_key = 'wp_capabilities' THEN um.meta_value END) AS roles
                FROM $users_table u
                LEFT JOIN $usermeta_table um 
                    ON um.user_id = u.ID
                WHERE u.ID = %d
                AND um.meta_key IN ('first_name', 'last_name', 'wp_capabilities')
                GROUP BY u.ID, u.user_email, u.user_registered;",
                $user_id
                ));
        
        if (!$user) {
            return false;
        }
        
        
        return array(
            'legacy_id' => $user->legacy_id,
            'first_name' => $user->first_name,
            'last_name' => $user->last_name,
            'user_email' => $user->user_email,
            'user_registered' => $user->user_registered,
            'roles' => $user->roles,
        );
    }
    
    /**
     * Extract access token from Authorization header.
     *
     * Parses the Authorization header to extract the Bearer token.
     * Supports both HTTP_AUTHORIZATION and REDIRECT_HTTP_AUTHORIZATION headers.
     *
     * @since 1.0.0
     * @return string|false The access token if found, false otherwise.
     */
    private function get_access_token_from_header() {
        $auth_header = '';
        
        // Check HTTP_AUTHORIZATION first
        if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
            $auth_header = sanitize_text_field(wp_unslash($_SERVER['HTTP_AUTHORIZATION']));
        }
        
        // Fallback to REDIRECT_HTTP_AUTHORIZATION for some server configurations
        if (empty($auth_header) && isset($_SERVER['REDIRECT_HTTP_AUTHORIZATION'])) {
            $auth_header = sanitize_text_field(wp_unslash($_SERVER['REDIRECT_HTTP_AUTHORIZATION']));
        }
        
        // Validate Bearer token format - strict pattern matching
        if (!empty($auth_header) && preg_match('/^Bearer\s+([A-Za-z0-9\-._~+\/]+=*)$/i', $auth_header, $matches)) {
            $token = trim($matches[1]);
            // Additional validation: token should be reasonable length (64-512 chars)
            if (strlen($token) >= 32 && strlen($token) <= 512) {
                return sanitize_text_field($token);
            }
        }
        
        return false;
    }
    
    /**
     * Check rate limiting for OAuth2 endpoints.
     *
     * Implements simple rate limiting using transients to prevent brute force attacks.
     *
     * @since 1.0.0
     * @param string $endpoint The endpoint identifier.
     * @return bool True if within rate limit, false otherwise.
     */
    private function check_rate_limit($endpoint) {
        $ip_address = $this->get_client_ip();
        $rate_limit_key = 'hc_oauth2_rate_limit_' . md5($endpoint . '_' . $ip_address);
        
        /**
         * Filter the rate limit threshold.
         *
         * @since 1.0.0
         * @param int    $limit    Maximum requests allowed. Default 100.
         * @param string $endpoint The endpoint identifier.
         */
        $limit = apply_filters('hc_oauth2_rate_limit', 100, $endpoint);
        
        /**
         * Filter the rate limit time window in seconds.
         *
         * @since 1.0.0
         * @param int    $window   Time window in seconds. Default 300 (5 minutes).
         * @param string $endpoint The endpoint identifier.
         */
        $window = apply_filters('hc_oauth2_rate_limit_window', 300, $endpoint);
        
        $current = get_transient($rate_limit_key);
        
        if ($current === false) {
            set_transient($rate_limit_key, 1, $window);
            return true;
        }
        
        if ($current >= $limit) {
            return false;
        }
        
        set_transient($rate_limit_key, $current + 1, $window);
        return true;
    }
    
    /**
     * Get client IP address securely.
     *
     * @since 1.0.0
     * @return string The client IP address.
     */
    private function get_client_ip() {
        $ip_keys = array(
            'HTTP_CF_CONNECTING_IP', // Cloudflare
            'HTTP_X_REAL_IP',
            'HTTP_X_FORWARDED_FOR',
            'REMOTE_ADDR'
        );
        
        foreach ($ip_keys as $key) {
            if (isset($_SERVER[$key]) && !empty($_SERVER[$key])) {
                $ip = sanitize_text_field(wp_unslash($_SERVER[$key]));
                // Handle comma-separated IPs (X-Forwarded-For)
                if (strpos($ip, ',') !== false) {
                    $ips = explode(',', $ip);
                    $ip = trim($ips[0]);
                }
                // Validate IP address
                if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                    return $ip;
                } elseif (filter_var($ip, FILTER_VALIDATE_IP)) {
                    return $ip;
                }
            }
        }
        
        return '0.0.0.0';
    }
    
    /**
     * Log failed authentication attempts for security monitoring.
     *
     * @since 1.0.0
     * @param string $endpoint The endpoint where the failure occurred.
     * @param string $client_id The client ID (may be empty).
     * @return void
     */
    private function log_failed_auth_attempt($endpoint, $client_id = '') {
        $ip_address = $this->get_client_ip();
        $log_key = 'hc_oauth2_failed_auth_' . md5($endpoint . '_' . $ip_address . '_' . $client_id);
        
        $attempts = get_transient($log_key);
        if ($attempts === false) {
            set_transient($log_key, 1, 3600); // 1 hour
        } else {
            set_transient($log_key, $attempts + 1, 3600);
            
            // Log to error log if multiple failures
            if ($attempts >= 5) {
                // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
                error_log(sprintf(
                    'HC-OAuth2-Server: Multiple failed authentication attempts from IP %s for endpoint %s (client: %s)',
                    $ip_address,
                    $endpoint,
                    $client_id ?: 'unknown'
                ));
            }
        }
        
        /**
         * Fires when a failed authentication attempt is detected.
         *
         * @since 1.0.0
         * @param string $endpoint  The endpoint identifier.
         * @param string $client_id The client ID.
         * @param string $ip_address The IP address.
         * @param int    $attempts  Number of attempts.
         */
        do_action('hc_oauth2_failed_auth_attempt', $endpoint, $client_id, $ip_address, $attempts + 1);
    }
    
    /**
     * Delete an authorization code from the database.
     *
     * Removes the authorization code after it has been used to exchange for tokens.
     *
     * @since 1.0.0
     * @param string $code The authorization code to delete.
     * @return void
     */
    private function delete_authorization_code($code) {
        global $wpdb;
        
        $codes_table = $wpdb->prefix . 'oauth2_codes';
        
        $wpdb->delete(
            $codes_table,
            array('code' => $code),
            array('%s')
        );
    }
    
    /**
     * Delete an access token from the database.
     *
     * Removes the access token, typically after generating a new one via refresh token.
     *
     * @since 1.0.0
     * @param string $access_token The access token to delete.
     * @return void
     */
    private function delete_access_token($access_token) {
        global $wpdb;
        
        $tokens_table = $wpdb->prefix . 'oauth2_tokens';
        
        $wpdb->delete(
            $tokens_table,
            array('access_token' => $access_token),
            array('%s')
        );
    }
    
    /**
     * Revoke all tokens for a specific user and client.
     *
     * Deletes all access and refresh tokens associated with a specific
     * user and client combination.
     *
     * @since 1.0.0
     * @param int    $user_id   The WordPress user ID.
     * @param string $client_id The OAuth2 client ID.
     * @return void
     */
    private function revoke_user_client_tokens($user_id, $client_id) {
        global $wpdb;
        
        $tokens_table = $wpdb->prefix . 'oauth2_tokens';
        
        $wpdb->delete(
            $tokens_table,
            array(
                'user_id' => $user_id,
                'client_id' => $client_id
            ),
            array('%d', '%s')
        );
    }
    
    /**
     * Revoke all tokens for a user across all clients.
     *
     * Deletes all access and refresh tokens associated with a user,
     * regardless of which client they were issued for.
     *
     * @since 1.0.0
     * @param int $user_id The WordPress user ID.
     * @return void
     */
    private function revoke_all_user_tokens($user_id) {
        global $wpdb;
        
        $tokens_table = $wpdb->prefix . 'oauth2_tokens';
        
        $wpdb->delete(
            $tokens_table,
            array('user_id' => $user_id),
            array('%d')
        );
    }
    
    /**
     * Send OAuth2 error response.
     *
     * Returns an error response either by redirecting to the redirect_uri
     * with error parameters, or by displaying an error page.
     *
     * @since 1.0.0
     * @param string $error            The error code.
     * @param string $error_description The error description.
     * @param string $redirect_uri     Optional. The redirect URI to send error to.
     * @param string $state            Optional. The state parameter.
     * @return void
     */
    private function oauth_error($error, $error_description, $redirect_uri = '', $state = '') {
        if (!empty($redirect_uri)) {
            $redirect_url = add_query_arg(array(
                'error' => $error,
                'error_description' => urlencode($error_description),
                'state' => $state
            ), $redirect_uri);
            
            wp_safe_redirect($redirect_url);
            exit;
        } else {
            wp_die(esc_html($error_description), esc_html__('OAuth2 Error', 'hc-oauth2-server'), array('response' => 400));
        }
    }
    
    /**
     * Send OAuth2 token endpoint error response.
     *
     * Returns a JSON error response for token endpoint requests.
     *
     * @since 1.0.0
     * @param string $error            The error code.
     * @param string $error_description The error description.
     * @return void
     */
    private function token_error($error, $error_description) {
        // Set security headers
        $this->set_security_headers();
        
        header('Content-Type: application/json');
        status_header(400);
        
        // Prevent information leakage - use generic messages for certain errors
        $safe_description = $error_description;
        if (in_array($error, array('invalid_client', 'invalid_grant'), true)) {
            // Use generic message to prevent enumeration attacks
            $safe_description = __('Authentication failed', 'hc-oauth2-server');
        }
        
        echo wp_json_encode(array(
            'error' => $error,
            'error_description' => $safe_description
        ));
        exit;
    }
    
    /**
     * Send OAuth2 token endpoint success response.
     *
     * Returns a JSON success response with access token, refresh token,
     * and related information.
     *
     * @since 1.0.0
     * @param array $token_data The token data to return.
     * @return void
     */
    private function token_success($token_data) {
        // Set security headers
        $this->set_security_headers();
        
        header('Content-Type: application/json');
        
        echo wp_json_encode($token_data);
        exit;
    }
    
    /**
     * Send OAuth2 userinfo endpoint error response.
     *
     * Returns a JSON error response for userinfo endpoint requests.
     *
     * @since 1.0.0
     * @param string $error            The error code.
     * @param string $error_description The error description.
     * @return void
     */
    private function userinfo_error($error, $error_description) {
        // Set security headers
        $this->set_security_headers();
        
        header('Content-Type: application/json');
        status_header(401);
        
        echo wp_json_encode(array(
            'error' => $error,
            'error_description' => $error_description
        ));
        exit;
    }
    
    /**
     * Send OAuth2 userinfo endpoint success response.
     *
     * Returns a JSON success response with user information.
     *
     * @since 1.0.0
     * @param array $user_info The user information to return.
     * @return void
     */
    private function userinfo_success($user_info) {
        // Set security headers
        $this->set_security_headers();
        
        header('Content-Type: application/json');
        
        echo wp_json_encode($user_info);
        exit;
    }
    
    /**
     * Send OAuth2 logout endpoint error response.
     *
     * Returns a JSON error response for logout endpoint requests.
     *
     * @since 1.0.0
     * @param string $error            The error code.
     * @param string $error_description The error description.
     * @return void
     */
    private function logout_error($error, $error_description) {
        // Set security headers
        $this->set_security_headers();
        
        header('Content-Type: application/json');
        status_header(400);
        
        echo wp_json_encode(array(
            'error' => $error,
            'error_description' => $error_description
        ));
        exit;
    }
    
    /**
     * Send OAuth2 logout endpoint success response.
     *
     * Returns a JSON success response confirming logout.
     *
     * @since 1.0.0
     * @return void
     */
    private function logout_success() {
        // Set security headers
        $this->set_security_headers();
        
        header('Content-Type: application/json');
        
        echo wp_json_encode(array(
            'success' => true,
            'message' => __('Successfully logged out', 'hc-oauth2-server')
        ));
        exit;
    }
    
    /**
     * Set security headers for OAuth2 API responses.
     *
     * @since 1.0.0
     * @return void
     */
    private function set_security_headers() {
        // Prevent clickjacking
        header('X-Frame-Options: DENY');
        
        // Prevent MIME type sniffing
        header('X-Content-Type-Options: nosniff');
        
        // XSS Protection
        header('X-XSS-Protection: 1; mode=block');
        
        // Referrer Policy
        header('Referrer-Policy: strict-origin-when-cross-origin');
        
        // Content Security Policy
        header("Content-Security-Policy: default-src 'self'");
        
        // Prevent caching of sensitive responses
        header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
        header('Pragma: no-cache');
        header('Expires: 0');
    }

    /**
     * Handle OAuth2 login redirect after successful WordPress login.
     *
     * Checks if there are stored OAuth2 parameters from an interrupted
     * authorization flow and redirects back to the authorization endpoint.
     *
     * @since 1.0.0
     * @param string           $redirect_to          The default redirect URL.
     * @param string           $requested_redirect_to The originally requested redirect URL.
     * @param WP_User|WP_Error  $user                The logged-in user or error object.
     * @return string The redirect URL.
     */
    public function handle_oauth2_login_redirect($redirect_to, $requested_redirect_to, $user) {
        // Check if we have stored OAuth2 parameters
        $oauth_params = $this->get_stored_oauth_params();
        
        if ($oauth_params && !is_wp_error($user)) {
            // Clear the stored parameters
            $this->clear_stored_oauth_params();
            
            // Reconstruct the OAuth2 authorization URL
            $auth_url = add_query_arg(array(
                'response_type' => 'code',
                'client_id' => $oauth_params['client_id'],
                'redirect_uri' => $oauth_params['redirect_uri'],
                'scope' => $oauth_params['scope'],
                'state' => $oauth_params['state']
            ), home_url('/oauth2/authorize'));
            
            return $auth_url;
        }
        
        return $redirect_to;
    }

    /**
     * Handle OAuth2 login redirect for WooCommerce login.
     *
     * Similar to handle_oauth2_login_redirect but specifically for WooCommerce
     * login flows. Checks for stored OAuth2 parameters and redirects accordingly.
     *
     * @since 1.0.0
     * @param string          $redirect_to The default redirect URL.
     * @param WP_User|WP_Error $user        The logged-in user or error object.
     * @return string The redirect URL.
     */
    public function handle_woocommerce_oauth2_login_redirect($redirect_to, $user) {
        // Check if we have stored OAuth2 parameters
        $oauth_params = $this->get_stored_oauth_params();
        
        if ($oauth_params && is_object($user) && !is_wp_error($user)) {
            // Clear the stored parameters
            $this->clear_stored_oauth_params();
            
            // Reconstruct the OAuth2 authorization URL
            $auth_url = add_query_arg(array(
                'response_type' => 'code',
                'client_id' => $oauth_params['client_id'],
                'redirect_uri' => $oauth_params['redirect_uri'],
                'scope' => $oauth_params['scope'],
                'state' => $oauth_params['state']
            ), home_url('/oauth2/authorize'));
            
            return $auth_url;
        }
        
        return $redirect_to;
    }
} 