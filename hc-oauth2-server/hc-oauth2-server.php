<?php
/**
 * Plugin Name: WP OAuth2 Server - OAuth2 Authentication (Login via WordPress)
 * Plugin URI: https://larawizard.hashnode.dev/
 * Description: A complete OAuth 2.0 authorization server implementation for WordPress. Provides secure authentication and authorization for third-party applications using the authorization code flow. Features include client management, token generation and validation, user information endpoints, logout support, and webhook integrations for user and order events.
 * Version: 1.0.0
 * Author: Harsh Chandra
 * Author URI: https://larawizard.hashnode.dev/
 * License: GPL v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: hc-oauth2-server
 * Requires at least: 5.0
 * Requires PHP: 7.2
 * Network: false
 */

// Prevent direct access
if (!defined('ABSPATH')) { exit; }

// Define plugin constants
define('HC_OAUTH2_SERVER_VERSION', '1.0.0');
define('HC_OAUTH2_SERVER_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('HC_OAUTH2_SERVER_PLUGIN_URL', plugin_dir_url(__FILE__));

// Include required files
require_once HC_OAUTH2_SERVER_PLUGIN_DIR . 'includes/class-hc-oauth2-main.php';
require_once HC_OAUTH2_SERVER_PLUGIN_DIR . 'includes/class-hc-oauth2-admin.php';
require_once HC_OAUTH2_SERVER_PLUGIN_DIR . 'includes/class-hc-oauth2-auth-handler.php';
require_once HC_OAUTH2_SERVER_PLUGIN_DIR . 'includes/class-hc-webhook-handler.php';

/**
 * Load plugin text domain for translations.
 *
 * Loads the plugin's translated strings from the languages directory.
 * The text domain is 'hc-oauth2-server'.
 *
 * @since 1.0.0
 * @return void
 */
function hc_oauth2_server_load_textdomain() {
    load_plugin_textdomain('hc-oauth2-server', false, dirname(plugin_basename(__FILE__)) . '/languages'
    );
}
add_action('plugins_loaded', 'hc_oauth2_server_load_textdomain');

/**
 * Initialize the OAuth2 Server plugin.
 *
 * Initializes all plugin components including the main server class,
 * authentication handler, admin interface, and webhook handler.
 *
 * @since 1.0.0
 * @return void
 */
function hc_oauth2_server_init() {
    $plugin = new HC_OAuth2_Server();
    $plugin->init();
    
    // Initialize auth handler early to ensure login redirect hook is registered
    new HC_OAuth2_Auth_Handler();
    
    // Initialize admin interface
    if (is_admin()) {
        $admin = new HC_OAuth2_Admin();
        $admin->init();
    }
    
    // Initialize Webhook handler (runs on both admin and frontend)
    $webhook_handler = new HC_OAuth2_Webhook_Handler();
    $webhook_handler->init();
}
add_action('plugins_loaded', 'hc_oauth2_server_init');

/**
 * Activation hook callback.
 *
 * Creates the necessary database tables when the plugin is activated.
 *
 * @since 1.0.0
 * @return void
 */
register_activation_hook(__FILE__, 'hc_oauth2_server_activate');
function hc_oauth2_server_activate() {
    HC_OAuth2_Server::create_tables();
}

/**
 * Deactivation hook callback.
 *
 * Performs cleanup tasks when the plugin is deactivated.
 * Currently, no cleanup is required, but this hook is available for future use.
 *
 * @since 1.0.0
 * @return void
 */
register_deactivation_hook(__FILE__, 'hc_oauth2_server_deactivate');
function hc_oauth2_server_deactivate() {
    // Clean up if needed
} 