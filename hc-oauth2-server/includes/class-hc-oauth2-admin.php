<?php
/**
 * OAuth2 Admin Interface
 *
 * Handles all WordPress admin interface functionality including:
 * - Admin menu creation
 * - Client management (add, delete, regenerate secrets)
 * - Token management (view, revoke)
 * - Webhook settings configuration
 * - Admin notices and messages
 *
 * @package HC_OAuth2_Server
 * @since 1.0.0
 */
if (!defined('ABSPATH')) {
    exit;
}

class HC_OAuth2_Admin {
    
    /**
     * Initialize admin interface hooks and actions.
     *
     * Registers WordPress admin hooks for menu creation, script enqueuing,
     * action handling, and admin notices.
     *
     * @since 1.0.0
     * @return void
     */
    public function init() {
        add_action('admin_menu', array($this, 'add_admin_menu'));
        add_action('admin_init', array($this, 'handle_admin_actions'));
        add_action('admin_enqueue_scripts', array($this, 'enqueue_admin_scripts'));
        add_action('admin_notices', array($this, 'display_admin_notices'));
    }
    
    /**
     * Add admin menu pages to WordPress admin.
     *
     * Creates the main OAuth2 Server menu and submenu pages for:
     * - Main server information page
     * - Auth Clients management
     * - Auth Tokens management
     * - Webhook Settings configuration
     *
     * @since 1.0.0
     * @return void
     */
    public function add_admin_menu() {
        add_menu_page(
            __('OAuth2 Server', 'hc-oauth2-server'),
            __('OAuth2 Server', 'hc-oauth2-server'),
            'manage_options',
            'hc-oauth2-server',
            array($this, 'admin_page'),
            'dashicons-shield',
            30
        );
        
        add_submenu_page(
            'hc-oauth2-server',
            __('Auth Clients', 'hc-oauth2-server'),
            __('Auth Clients', 'hc-oauth2-server'),
            'manage_options',
            'hc-oauth2-clients',
            array($this, 'clients_page')
        );
        
        add_submenu_page(
            'hc-oauth2-server',
            __('Auth Tokens', 'hc-oauth2-server'),
            __('Auth Tokens', 'hc-oauth2-server'),
            'manage_options',
            'hc-oauth2-tokens',
            array($this, 'tokens_page')
        );
        
        add_submenu_page(
            'hc-oauth2-server',
            __('Webhook Settings', 'hc-oauth2-server'),
            __('Webhook Settings', 'hc-oauth2-server'),
            'manage_options',
            'hc-webhook-settings',
            array($this, 'webhook_settings_page')
        );
    }
    
    /**
     * Enqueue admin scripts and styles.
     *
     * Loads jQuery and custom admin CSS for OAuth2 Server admin pages.
     *
     * @since 1.0.0
     * @param string $hook The current admin page hook.
     * @return void
     */
    public function enqueue_admin_scripts($hook) {
        if (strpos($hook, 'hc-oauth2-server') !== false || strpos($hook, 'hc-oauth2') !== false) {
            wp_enqueue_script('jquery');
            wp_enqueue_style('hc-oauth2-admin', HC_OAUTH2_SERVER_PLUGIN_URL . 'assets/admin.css', array(), HC_OAUTH2_SERVER_VERSION);
            
            // Enqueue script for client secret toggle functionality
            wp_add_inline_script('jquery', "
                (function($) {
                    $(document).ready(function() {
                        $('.toggle-secret').on('click', function(e) {
                            e.preventDefault();
                            var targetId = $(this).data('target');
                            var fullSecret = $('#secret-' + targetId);
                            var maskedSecret = $(this).siblings('.client-secret-masked');
                            var showText = $(this).find('.show-text');
                            var hideText = $(this).find('.hide-text');
                            
                            if (fullSecret.is(':visible')) {
                                fullSecret.hide();
                                maskedSecret.show();
                                showText.show();
                                hideText.hide();
                            } else {
                                fullSecret.show();
                                maskedSecret.hide();
                                showText.hide();
                                hideText.show();
                            }
                        });
                    });
                })(jQuery);
            ");
        }
    }
    
    /**
     * Display admin notices for success and error messages.
     *
     * Shows dismissible notices based on URL parameters for:
     * - Client operations (add, delete, regenerate secret)
     * - Token operations (revoke)
     * - Settings operations (save)
     * - Error conditions (missing fields, invalid nonce, etc.)
     *
     * @since 1.0.0
     * @return void
     */
    public function display_admin_notices() {
        $screen = get_current_screen();
        
        // Only show notices on our plugin pages
        if (!$screen || strpos($screen->id, 'hc-oauth2') === false) {
            return;
        }
        
        // Check for success messages
        if (isset($_GET['message'])) {
            $message = sanitize_text_field($_GET['message']);
            $type = 'success';
            $text = '';
            
            switch ($message) {
                case 'client_added':
                    $text = __('OAuth2 client has been successfully added.', 'hc-oauth2-server');
                    break;
                case 'client_deleted':
                    $text = __('OAuth2 client has been successfully deleted.', 'hc-oauth2-server');
                    break;
                case 'secret_regenerated':
                    $text = __('Client secret has been successfully regenerated.', 'hc-oauth2-server');
                    break;
                case 'token_revoked':
                    $text = __('Access token has been successfully revoked.', 'hc-oauth2-server');
                    break;
                case 'settings_saved':
                    $text = __('Settings have been successfully saved.', 'hc-oauth2-server');
                    break;
            }
            
            if ($text) {
                printf('<div class="notice notice-%s is-dismissible"><p>%s</p></div>', $type, esc_html($text));
            }
        }
        
        // Check for error messages
        if (isset($_GET['error'])) {
            $error = sanitize_text_field($_GET['error']);
            $text = '';
            
            switch ($error) {
                case 'missing_fields':
                    $text = __('Error: Missing required fields. Please fill in all required information.', 'hc-oauth2-server');
                    break;
                case 'add_failed':
                    $text = __('Error: Failed to add client. Please try again.', 'hc-oauth2-server');
                    break;
                case 'delete_failed':
                    $text = __('Error: Failed to delete client. Please try again.', 'hc-oauth2-server');
                    break;
                case 'regenerate_failed':
                    $text = __('Error: Failed to regenerate client secret. Please try again.', 'hc-oauth2-server');
                    break;
                case 'revoke_failed':
                    $text = __('Error: Failed to revoke token. Please try again.', 'hc-oauth2-server');
                    break;
                case 'save_failed':
                    $text = __('Error: Failed to save settings. Please try again.', 'hc-oauth2-server');
                    break;
                case 'invalid_nonce':
                    $text = __('Error: Security check failed. Please try again.', 'hc-oauth2-server');
                    break;
            }
            
            if ($text) {
                printf('<div class="notice notice-error is-dismissible"><p>%s</p></div>', esc_html($text));
            }
        }
    }
    
    /**
     * Handle admin form submissions and actions.
     *
     * Processes POST requests for:
     * - Adding new OAuth2 clients
     * - Deleting clients
     * - Regenerating client secrets
     * - Revoking access tokens
     *
     * Validates nonces and user capabilities before processing.
     *
     * @since 1.0.0
     * @return void
     */
    public function handle_admin_actions() {
        if (!current_user_can('manage_options')) {
            return;
        }
        
        // Only process OAuth2 actions if we're on an OAuth2 admin page or if the action is specifically for OAuth2
        $current_page = isset($_GET['page']) ? sanitize_text_field($_GET['page']) : '';
        $is_oauth2_page = strpos($current_page, 'hc-oauth2-') === 0 || strpos($current_page, 'hc-webhook') === 0;
        
        if (isset($_POST['action']) && isset($_POST['_wpnonce']) && $is_oauth2_page) {
            $action = sanitize_text_field($_POST['action']);
            if (wp_verify_nonce($_POST['_wpnonce'], 'hc_oauth2_server_action')) {
                switch ($action) {
                    case 'add_client':
                        $this->add_client();
                        break;
                    case 'delete_client':
                        $this->delete_client();
                        break;
                    case 'regenerate_secret':
                        $this->regenerate_client_secret();
                        break;
                    case 'revoke_token':
                        $this->revoke_token();
                        break;
                    case 'save_settings':
                        $this->save_webhook_settings();
                        break;
                }
            } else {
                // Invalid nonce
                $redirect_page = isset($_POST['action']) ? $this->get_current_page_from_action(sanitize_text_field($_POST['action'])) : 'hc-oauth2-server-clients';
                wp_redirect(admin_url('admin.php?page=' . $redirect_page . '&error=invalid_nonce'));
                exit;
            }
        }
    }
    
    /**
     * Get the admin page slug based on the action being performed.
     *
     * Maps action types to their corresponding admin page slugs
     * for redirect purposes.
     *
     * @since 1.0.0
     * @param string $action The action being performed.
     * @return string The admin page slug.
     */
    private function get_current_page_from_action($action) {
        switch ($action) {
            case 'add_client':
            case 'delete_client':
            case 'regenerate_secret':
                return 'hc-oauth2-clients';
            case 'revoke_token':
                return 'hc-oauth2-tokens';
            case 'save_settings':
                return 'hc-webhook-settings';
            default:
                return 'hc-oauth2-clients';
        }
    }
    
    /**
     * Render the main OAuth2 Server admin page.
     *
     * Displays server endpoint information and quick statistics
     * including registered clients count and active tokens count.
     *
     * @since 1.0.0
     * @return void
     */
    public function admin_page() {
        ?>
        <div class="wrap">
            <h1><?php echo esc_html__('OAuth2 Server', 'hc-oauth2-server'); ?></h1>
            
            <div class="card">
                <h2><?php echo esc_html__('Server Information', 'hc-oauth2-server'); ?></h2>
                <table class="form-table">
                    <tr>
                        <th><?php echo esc_html__('Authorization Endpoint', 'hc-oauth2-server'); ?></th>
                        <td><code><?php echo esc_url(home_url('/oauth2/authorize')); ?></code></td>
                    </tr>
                    <tr>
                        <th><?php echo esc_html__('Token Endpoint', 'hc-oauth2-server'); ?></th>
                        <td><code><?php echo esc_url(home_url('/oauth2/token')); ?></code></td>
                    </tr>
                    <tr>
                        <th><?php echo esc_html__('Userinfo Endpoint', 'hc-oauth2-server'); ?></th>
                        <td><code><?php echo esc_url(home_url('/oauth2/userinfo')); ?></code></td>
                    </tr>
                    <tr>
                        <th><?php echo esc_html__('Logout Endpoint', 'hc-oauth2-server'); ?></th>
                        <td><code><?php echo esc_url(home_url('/oauth2/logout')); ?></code></td>
                    </tr>
                </table>
            </div>
            
            <div class="card">
                <h2><?php echo esc_html__('Quick Stats', 'hc-oauth2-server'); ?></h2>
                <?php
                global $wpdb;
                $clients_table = $wpdb->prefix . 'oauth2_clients';
                $tokens_table = $wpdb->prefix . 'oauth2_tokens';
                
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
                $client_count = $wpdb->get_var("SELECT COUNT(*) FROM $clients_table");
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
                $active_tokens = $wpdb->get_var("SELECT COUNT(*) FROM $tokens_table WHERE expires_at > NOW()");
                ?>
                <p><strong><?php echo esc_html__('Registered Clients:', 'hc-oauth2-server'); ?></strong> <?php echo esc_html($client_count); ?></p>
                <p><strong><?php echo esc_html__('Active Tokens:', 'hc-oauth2-server'); ?></strong> <?php echo esc_html($active_tokens); ?></p>
            </div>
        </div>
        <?php
    }
    
    /**
     * Render the OAuth2 Clients management page.
     *
     * Displays a list of all registered OAuth2 clients with options to:
     * - Add new clients
     * - Regenerate client secrets
     * - Delete clients
     *
     * @since 1.0.0
     * @return void
     */
    public function clients_page() {
        global $wpdb;
        $clients_table = $wpdb->prefix . 'oauth2_clients';
        
        $action = isset($_GET['action']) ? sanitize_text_field($_GET['action']) : '';
        if ($action === 'add') {
            $this->client_form();
            return;
        }
        
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
        $clients = $wpdb->get_results("SELECT * FROM $clients_table ORDER BY created_at DESC");
        ?>
        <div class="wrap">
            <h1><?php echo esc_html__('OAuth2 Clients', 'hc-oauth2-server'); ?></h1>
            <a href="?page=hc-oauth2-clients&action=add" class="page-title-action mb-10"><?php echo esc_html__('Add New Client', 'hc-oauth2-server'); ?></a>
            
            <table class="wp-list-table widefat fixed striped">
                <thead>
                    <tr>
                        <th><?php echo esc_html__('Name', 'hc-oauth2-server'); ?></th>
                        <th><?php echo esc_html__('Client ID', 'hc-oauth2-server'); ?></th>
                        <th><?php echo esc_html__('Client Secret', 'hc-oauth2-server'); ?></th>
                        <th><?php echo esc_html__('Redirect URI', 'hc-oauth2-server'); ?></th>
                        <th><?php echo esc_html__('Created', 'hc-oauth2-server'); ?></th>
                        <th><?php echo esc_html__('Actions', 'hc-oauth2-server'); ?></th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($clients as $client): ?>
                    <tr>
                        <td><?php echo esc_html($client->name); ?></td>
                        <td><code><?php echo esc_html($client->client_id); ?></code></td>
                        <td>
                            <code class="client-secret-masked">
                                <?php 
                                // Mask client secret for security - show only first 8 and last 4 characters
                                $secret = $client->client_secret;
                                $length = strlen($secret);
                                if ($length > 12) {
                                    echo esc_html(substr($secret, 0, 8) . str_repeat('*', $length - 12) . substr($secret, -4));
                                } else {
                                    echo esc_html(str_repeat('*', $length));
                                }
                                ?>
                            </code>
                            <button type="button" class="button button-small toggle-secret" data-target="<?php echo esc_attr($client->id); ?>" style="margin-left: 5px;">
                                <span class="show-text"><?php echo esc_html__('Show', 'hc-oauth2-server'); ?></span>
                                <span class="hide-text" style="display:none;"><?php echo esc_html__('Hide', 'hc-oauth2-server'); ?></span>
                            </button>
                            <span class="full-secret" id="secret-<?php echo esc_attr($client->id); ?>" style="display:none;">
                                <code><?php echo esc_html($client->client_secret); ?></code>
                            </span>
                        </td>
                        <td><?php echo esc_url($client->redirect_uri); ?></td>
                        <td><?php echo esc_html($client->created_at); ?></td>
                        <td>
                            <form method="post" style="display:inline;">
                                <?php wp_nonce_field('hc_oauth2_server_action'); ?>
                                <input type="hidden" name="action" value="regenerate_secret">
                                <input type="hidden" name="client_id" value="<?php echo esc_attr($client->client_id); ?>">
                                <button type="submit" class="button button-small"><?php echo esc_html__('Regenerate Secret', 'hc-oauth2-server'); ?></button>
                            </form>
                            
                            <form method="post" style="display:inline;" onsubmit="return confirm('<?php echo esc_js(__('Are you sure you want to delete this client?', 'hc-oauth2-server')); ?>');">
                                <?php wp_nonce_field('hc_oauth2_server_action'); ?>
                                <input type="hidden" name="action" value="delete_client">
                                <input type="hidden" name="client_id" value="<?php echo esc_attr($client->client_id); ?>">
                                <button type="submit" class="button button-small button-link-delete"><?php echo esc_html__('Delete', 'hc-oauth2-server'); ?></button>
                            </form>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                    <?php if (empty($clients)): ?>
                    <tr>
                        <td colspan="6">
                            <div class="no-results-found">
                                <p><?php echo esc_html__('No clients found.', 'hc-oauth2-server'); ?></p>
                                <a href="?page=hc-oauth2-clients&action=add" class="button button-small"><?php echo esc_html__('Add New Client', 'hc-oauth2-server'); ?></a>
                            </div>
                        </td>
                    </tr>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
        <?php
    }
    
    /**
     * Render the form for adding a new OAuth2 client.
     *
     * Displays a form with fields for client name and redirect URI.
     * Handles form submission to add new clients.
     *
     * @since 1.0.0
     * @return void
     */
    private function client_form() {
        // Form submission for adding a client is handled by handle_admin_actions()
        // via the admin_init hook, which runs before any output is sent.
        ?>
        <div class="wrap">
            <h1><?php echo esc_html__('Add New OAuth2 Client', 'hc-oauth2-server'); ?></h1>
            
            <form method="post">
                <?php wp_nonce_field('hc_oauth2_server_action'); ?>
                <input type="hidden" name="action" value="add_client">
                
                <table class="form-table">
                    <tr>
                        <th><label for="client_name"><?php echo esc_html__('Client Name', 'hc-oauth2-server'); ?></label></th>
                        <td>
                            <input type="text" id="client_name" name="client_name" class="regular-text" required>
                            <p class="description"><?php echo esc_html__('A descriptive name for this client application.', 'hc-oauth2-server'); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th><label for="redirect_uri"><?php echo esc_html__('Redirect URI', 'hc-oauth2-server'); ?></label></th>
                        <td>
                            <input type="url" id="redirect_uri" name="redirect_uri" class="regular-text" required>
                            <p class="description"><?php echo esc_html__('The callback URL where users will be redirected after authorization.', 'hc-oauth2-server'); ?></p>
                        </td>
                    </tr>
                </table>
                
                <p class="submit">
                    <input type="submit" name="submit" id="submit" class="button button-primary" value="<?php echo esc_attr__('Add Client', 'hc-oauth2-server'); ?>">
                    <a href="?page=hc-oauth2-clients" class="button"><?php echo esc_html__('Cancel', 'hc-oauth2-server'); ?></a>
                </p>
            </form>
        </div>
        <?php
    }
    
    /**
     * Render the OAuth2 Tokens management page.
     *
     * Displays a list of all access tokens with information about:
     * - Associated user
     * - Client ID
     * - Token status (active/expired)
     * - Expiration date
     * - Creation date
     *
     * Provides option to revoke tokens.
     *
     * @since 1.0.0
     * @return void
     */
    public function tokens_page() {
        global $wpdb;
        $tokens_table = $wpdb->prefix . 'oauth2_tokens';
        $users_table = $wpdb->prefix . 'users';
        
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
        $tokens = $wpdb->get_results("
            SELECT t.*, u.display_name 
            FROM $tokens_table t 
            LEFT JOIN $users_table u ON t.user_id = u.ID 
            ORDER BY t.created_at DESC
        ");
        ?>
        <div class="wrap">
            <h1><?php echo esc_html__('OAuth2 Tokens', 'hc-oauth2-server'); ?></h1>
            
            <table class="wp-list-table widefat fixed striped">
                <thead>
                    <tr>
                        <th><?php echo esc_html__('User', 'hc-oauth2-server'); ?></th>
                        <th><?php echo esc_html__('Client ID', 'hc-oauth2-server'); ?></th>
                        <th><?php echo esc_html__('Access Token', 'hc-oauth2-server'); ?></th>
                        <th><?php echo esc_html__('Expires', 'hc-oauth2-server'); ?></th>
                        <th><?php echo esc_html__('Created', 'hc-oauth2-server'); ?></th>
                        <th><?php echo esc_html__('Actions', 'hc-oauth2-server'); ?></th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($tokens as $token): ?>
                    <tr>
                        <td><?php echo esc_html($token->display_name); ?></td>
                        <td><?php echo esc_html($token->client_id); ?></td>
                        <td><code><?php echo esc_html(substr($token->access_token, 0, 20)) . '...'; ?></code></td>
                        <td>
                            <?php 
                            $expires = strtotime($token->expires_at);
                            $now = time();
                            $status = $expires > $now ? __('Active', 'hc-oauth2-server') : __('Expired', 'hc-oauth2-server');
                            $class = $expires > $now ? 'active' : 'expired';
                            ?>
                            <span class="token-status <?php echo esc_attr($class); ?>">
                                <?php echo esc_html($status); ?> (<?php echo esc_html(gmdate('Y-m-d H:i:s', $expires)); ?>)
                            </span>
                        </td>
                        <td><?php echo esc_html($token->created_at); ?></td>
                        <td>
                            <form method="post" style="display:inline;" onsubmit="return confirm('<?php echo esc_js(__('Are you sure you want to revoke this token?', 'hc-oauth2-server')); ?>');">
                                <?php wp_nonce_field('hc_oauth2_server_action'); ?>
                                <input type="hidden" name="action" value="revoke_token">
                                <input type="hidden" name="access_token" value="<?php echo esc_attr($token->access_token); ?>">
                                <button type="submit" class="button button-small button-link-delete"><?php echo esc_html__('Revoke', 'hc-oauth2-server'); ?></button>
                            </form>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                    <?php if (empty($tokens)): ?>
                    <tr>
                        <td colspan="6">
                            <div class="no-results-found">
                                <p><?php echo esc_html__('No tokens found.', 'hc-oauth2-server'); ?></p>
                            </div>
                        </td>
                    </tr>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
        <?php
    }
    
    
    /**
     * Add a new OAuth2 client to the database.
     *
     * Validates input, generates client_id and client_secret,
     * and stores the client in the database.
     *
     * @since 1.0.0
     * @return void Redirects to clients page with success or error message.
     */
    private function add_client() {
        global $wpdb;
        
        $name = isset($_POST['client_name']) ? sanitize_text_field($_POST['client_name']) : '';
        $redirect_uri = isset($_POST['redirect_uri']) ? esc_url_raw($_POST['redirect_uri']) : '';
        
        if (empty($name) || empty($redirect_uri)) {
            wp_safe_redirect(admin_url('admin.php?page=hc-oauth2-clients&error=missing_fields'));
            exit;
        }
        
        /**
         * Filter the client data before inserting into database.
         *
         * @since 1.0.0
         * @param array $client_data Array containing name and redirect_uri.
         */
        $client_data = apply_filters('hc_oauth2_client_create_data', array(
            'name' => $name,
            'redirect_uri' => $redirect_uri
        ));
        
        $name = isset($client_data['name']) ? sanitize_text_field($client_data['name']) : $name;
        $redirect_uri = isset($client_data['redirect_uri']) ? esc_url_raw($client_data['redirect_uri']) : $redirect_uri;
        
        $client_id = HC_OAuth2_Server::generate_random_string(32);
        $client_secret = HC_OAuth2_Server::generate_random_string(32);
        
        /**
         * Filter the generated client ID.
         *
         * @since 1.0.0
         * @param string $client_id The generated client ID.
         * @param string $name      The client name.
         */
        $client_id = apply_filters('hc_oauth2_client_id', $client_id, $name);
        
        /**
         * Filter the generated client secret.
         *
         * @since 1.0.0
         * @param string $client_secret The generated client secret.
         * @param string $name          The client name.
         */
        $client_secret = apply_filters('hc_oauth2_client_secret', $client_secret, $name);
        
        /**
         * Fires before creating a new OAuth2 client.
         *
         * @since 1.0.0
         * @param string $client_id     The client ID.
         * @param string $client_secret The client secret.
         * @param string $name          The client name.
         * @param string $redirect_uri  The redirect URI.
         */
        do_action('hc_oauth2_before_client_create', $client_id, $client_secret, $name, $redirect_uri);
        
        $clients_table = $wpdb->prefix . 'oauth2_clients';
        
        $result = $wpdb->insert(
            $clients_table,
            array(
                'client_id' => $client_id,
                'client_secret' => $client_secret,
                'redirect_uri' => $redirect_uri,
                'name' => $name
            ),
            array('%s', '%s', '%s', '%s')
        );
        
        if ($result) {
            /**
             * Fires after a new OAuth2 client is successfully created.
             *
             * @since 1.0.0
             * @param string $client_id     The client ID.
             * @param string $client_secret The client secret.
             * @param string $name          The client name.
             * @param string $redirect_uri  The redirect URI.
             */
            do_action('hc_oauth2_after_client_create', $client_id, $client_secret, $name, $redirect_uri);
            
            wp_safe_redirect(admin_url('admin.php?page=hc-oauth2-clients&message=client_added'));
            exit;
        } else {
            wp_safe_redirect(admin_url('admin.php?page=hc-oauth2-clients&error=add_failed'));
            exit;
        }
    }
    
    /**
     * Delete an OAuth2 client and all associated tokens.
     *
     * Removes the client from the database and also deletes
     * all access tokens associated with that client.
     *
     * @since 1.0.0
     * @return void Redirects to clients page with success or error message.
     */
    private function delete_client() {
        global $wpdb;
        
        $client_id = isset($_POST['client_id']) ? sanitize_text_field($_POST['client_id']) : '';
        
        if (empty($client_id)) {
            wp_safe_redirect(admin_url('admin.php?page=hc-oauth2-clients&error=missing_fields'));
            exit;
        }
        
        /**
         * Fires before deleting an OAuth2 client.
         *
         * @since 1.0.0
         * @param string $client_id The client ID to delete.
         */
        do_action('hc_oauth2_before_client_delete', $client_id);
        
        $clients_table = $wpdb->prefix . 'oauth2_clients';
        $tokens_table = $wpdb->prefix . 'oauth2_tokens';
        
        // Delete client
        $client_deleted = $wpdb->delete($clients_table, array('client_id' => $client_id), array('%s'));
        
        // Delete associated tokens
        $tokens_deleted = $wpdb->delete($tokens_table, array('client_id' => $client_id), array('%s'));
        
        if ($client_deleted !== false) {
            /**
             * Fires after an OAuth2 client is successfully deleted.
             *
             * @since 1.0.0
             * @param string $client_id The deleted client ID.
             */
            do_action('hc_oauth2_after_client_delete', $client_id);
            
            wp_safe_redirect(admin_url('admin.php?page=hc-oauth2-clients&message=client_deleted'));
        } else {
            wp_safe_redirect(admin_url('admin.php?page=hc-oauth2-clients&error=delete_failed'));
        }
        exit;
    }
    
    /**
     * Regenerate the secret for an OAuth2 client.
     *
     * Generates a new cryptographically secure client secret
     * and updates it in the database. Invalidates all existing
     * tokens for the client.
     *
     * @since 1.0.0
     * @return void Redirects to clients page with success or error message.
     */
    private function regenerate_client_secret() {
        global $wpdb;
        
        $client_id = isset($_POST['client_id']) ? sanitize_text_field($_POST['client_id']) : '';
        
        if (empty($client_id)) {
            wp_safe_redirect(admin_url('admin.php?page=hc-oauth2-clients&error=missing_fields'));
            exit;
        }
        
        $new_secret = HC_OAuth2_Server::generate_random_string(32);
        
        /**
         * Filter the new client secret before regenerating.
         *
         * @since 1.0.0
         * @param string $new_secret The generated new secret.
         * @param string $client_id  The client ID.
         */
        $new_secret = apply_filters('hc_oauth2_regenerate_client_secret', $new_secret, $client_id);
        
        /**
         * Fires before regenerating a client secret.
         *
         * @since 1.0.0
         * @param string $client_id  The client ID.
         * @param string $new_secret The new secret that will be set.
         */
        do_action('hc_oauth2_before_secret_regenerate', $client_id, $new_secret);
        
        $clients_table = $wpdb->prefix . 'oauth2_clients';
        
        $result = $wpdb->update(
            $clients_table,
            array('client_secret' => $new_secret),
            array('client_id' => $client_id),
            array('%s'),
            array('%s')
        );
        
        if ($result !== false) {
            /**
             * Fires after a client secret is successfully regenerated.
             *
             * @since 1.0.0
             * @param string $client_id  The client ID.
             * @param string $new_secret The new secret.
             */
            do_action('hc_oauth2_after_secret_regenerate', $client_id, $new_secret);
            
            wp_safe_redirect(admin_url('admin.php?page=hc-oauth2-clients&message=secret_regenerated'));
        } else {
            wp_safe_redirect(admin_url('admin.php?page=hc-oauth2-clients&error=regenerate_failed'));
        }
        exit;
    }
    
    /**
     * Revoke an access token.
     *
     * Removes the specified access token from the database,
     * effectively invalidating it for future requests.
     *
     * @since 1.0.0
     * @return void Redirects to tokens page with success or error message.
     */
    private function revoke_token() {
        global $wpdb;
        
        $access_token = isset($_POST['access_token']) ? sanitize_text_field($_POST['access_token']) : '';
        
        if (empty($access_token)) {
            wp_safe_redirect(admin_url('admin.php?page=hc-oauth2-tokens&error=missing_fields'));
            exit;
        }
        
        /**
         * Fires before revoking an access token from admin.
         *
         * @since 1.0.0
         * @param string $access_token The access token to revoke.
         */
        do_action('hc_oauth2_before_admin_token_revoke', $access_token);
        
        $tokens_table = $wpdb->prefix . 'oauth2_tokens';
        
        $result = $wpdb->delete($tokens_table, array('access_token' => $access_token), array('%s'));
        
        if ($result !== false) {
            /**
             * Fires after an access token is successfully revoked from admin.
             *
             * @since 1.0.0
             * @param string $access_token The revoked access token.
             */
            do_action('hc_oauth2_after_admin_token_revoke', $access_token);
            
            wp_safe_redirect(admin_url('admin.php?page=hc-oauth2-tokens&message=token_revoked'));
        } else {
            wp_safe_redirect(admin_url('admin.php?page=hc-oauth2-tokens&error=revoke_failed'));
        }
        exit;
    }
    
    /**
     * Render the Webhook Settings configuration page.
     *
     * Provides interface to configure webhook URLs for:
     * - Order completion notifications
     * - User profile and role change notifications
     *
     * Handles form submission to save webhook settings.
     *
     * @since 1.0.0
     * @return void
     */
    public function webhook_settings_page() {
        $current_user_webhook_url = get_option('hc_oauth2_server_user_webhook_url', '');
        ?>
        <div class="wrap">
            <h1><?php echo esc_html__('Webhook Settings', 'hc-oauth2-server'); ?></h1>
            
            <?php if (isset($_GET['message']) && $_GET['message'] === 'settings_saved'): ?>
                <div class="notice notice-success is-dismissible">
                    <p><?php echo esc_html__('Webhook settings have been saved successfully.', 'hc-oauth2-server'); ?></p>
                </div>
            <?php endif; ?>
            
            <form method="post" action="">
                <?php wp_nonce_field('hc_oauth2_server_action'); ?>
                <input type="hidden" name="action" value="save_settings">
                
                <table class="form-table">
                    <tr>
                        <th scope="row">
                            <label for="hc_oauth2_server_user_webhook_url"><?php echo esc_html__('User Webhook URL', 'hc-oauth2-server'); ?></label>
                        </th>
                        <td>
                            <input type="url" 
                                   id="hc_oauth2_server_user_webhook_url" 
                                   name="hc_oauth2_server_user_webhook_url" 
                                   value="<?php echo esc_attr($current_user_webhook_url); ?>" 
                                   class="regular-text" 
                                   placeholder="<?php echo esc_attr__('https://your-webhook-endpoint.com/webhook', 'hc-oauth2-server'); ?>" />
                            <p class="description">
                                <?php echo esc_html__('Enter the webhook URL where User Profile and roles notifications will be sent. The webhook will receive a POST request with user data and associated roles.', 'hc-oauth2-server'); ?>
                            </p>
                        </td>
                    </tr>
                </table>
                
                <?php submit_button(__('Save Settings', 'hc-oauth2-server')); ?>
            </form>
        </div>
        <?php
    }

    /**
     * Save webhook settings from the admin form.
     *
     * Processes the webhook settings form submission and redirects
     * back to the settings page with an appropriate message.
     *
     * @since 1.0.0
     * @return void
     */
    private function save_webhook_settings() {
        $hc_oauth2_server_user_webhook_url = isset($_POST['hc_oauth2_server_user_webhook_url']) ? sanitize_url($_POST['hc_oauth2_server_user_webhook_url']) : '';
        update_option('hc_oauth2_server_user_webhook_url', $hc_oauth2_server_user_webhook_url);
        wp_safe_redirect(admin_url('admin.php?page=hc-webhook-settings&message=settings_saved'));
        exit;
    }
} 