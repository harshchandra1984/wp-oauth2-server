<?php
/**
 * Webhook Handler for User Updates
 *
 * Handles WordPress user events and sends webhook notifications to configured URLs.
 * Monitors user profile updates, role changes, and new user registrations.
 *
 * @package HC_OAuth2_Server
 * @since 1.0.0
 */
if (!defined('ABSPATH')) {
    exit;
}

class HC_OAuth2_Webhook_Handler {
    
    /**
     * Initialize the webhook handler hooks.
     *
     * Registers WordPress hooks to monitor user-related events:
     * - Profile updates
     * - Role changes
     * - New user registrations
     *
     * @since 1.0.0
     * @return void
     */
    public function init() {        
        add_action('profile_update', array($this, 'handle_profile_update'), 10, 3);
        add_action('update_user_meta', array($this, 'handle_role_change'), 10, 4);
        add_action('user_register', array($this, 'handle_new_user_created'), 10, 1);
    }

    /**
     * Handle user profile update event.
     *
     * Triggered when a user profile is updated. Prepares and sends
     * a webhook notification with updated user information.
     *
     * @since 1.0.0
     * @param int    $user_id      The user ID that was updated.
     * @param object $old_user_data The previous user data.
     * @param array  $userData      The new user data.
     * @return void
     */
    public function handle_profile_update($user_id, $old_user_data, $userData) {
        $user = get_user_by('id', $user_id);
        if (!$user) {
            return;
        }

        // Prepare payload
        $payload = [
            'wp_id' => $user_id,
            'event_type' => 'profile_update',
            'user_email' => $user->user_email,
            'first_name' => get_user_meta($user_id, 'first_name', true),
            'last_name'  => get_user_meta($user_id, 'last_name', true),
            'roles'      => (array) $user->roles
        ];

        /**
         * Filter the webhook payload before sending profile update notification.
         *
         * @since 1.0.0
         * @param array  $payload  The webhook payload data.
         * @param object $user     The user object.
         * @param object $old_user_data The previous user data.
         */
        $payload = apply_filters('hc_oauth2_profile_update_webhook_payload', $payload, $user, $old_user_data);
        
        /**
         * Fires before sending profile update webhook.
         *
         * @since 1.0.0
         * @param array  $payload  The webhook payload data.
         * @param int    $user_id  The user ID.
         */
        do_action('hc_oauth2_before_profile_update_webhook', $payload, $user_id);

        $this->send_user_update_webhook($payload);
    }

    /**
     * Handle user role change event.
     *
     * Triggered when user meta is updated. Specifically monitors
     * capability changes which indicate role modifications.
     *
     * @since 1.0.0
     * @param int    $meta_id    The meta ID.
     * @param int    $user_id    The user ID.
     * @param string $meta_key  The meta key being updated.
     * @param mixed  $meta_value The new meta value.
     * @return void
     */
    public function handle_role_change($meta_id, $user_id, $meta_key, $meta_value) {
        global $wpdb;
        $cap_key = $wpdb->prefix . 'capabilities';
        // Checking only for Role Changes
        if ($meta_key === $cap_key && is_array($meta_value)) {
        
            $user = get_user_by('id', $user_id);
            if (!$user) {
                return;
            }

            // Prepare payload
            $payload = [
                'wp_id' => $user_id,
                'event_type' => 'role_change',
                'user_email' => $user->user_email,
                'first_name' => get_user_meta($user_id, 'first_name', true),
                'last_name'  => get_user_meta($user_id, 'last_name', true),
                'roles'      => $meta_value
            ];
            
            /**
             * Filter the webhook payload before sending role change notification.
             *
             * @since 1.0.0
             * @param array  $payload  The webhook payload data.
             * @param object $user     The user object.
             * @param string $meta_key The meta key that was updated.
             * @param mixed  $meta_value The new meta value (roles).
             */
            $payload = apply_filters('hc_oauth2_role_change_webhook_payload', $payload, $user, $meta_key, $meta_value);
            
            /**
             * Fires before sending role change webhook.
             *
             * @since 1.0.0
             * @param array  $payload  The webhook payload data.
             * @param int    $user_id  The user ID.
             */
            do_action('hc_oauth2_before_role_change_webhook', $payload, $user_id);
            
            $this->send_user_update_webhook($payload);
        }
    }
     
    /**
     * Handle new user creation event.
     *
     * Triggered when a new user is registered. Prepares and sends
     * a webhook notification with the new user information.
     *
     * @since 1.0.0
     * @param int $user_id The newly created user ID.
     * @return void
     */
    public function handle_new_user_created($user_id) {
        $user = get_user_by('id', $user_id);
        if (!$user) {
            return;
        }

        // Prepare payload
        $payload = [
            'wp_id' => $user_id,
            'event_type' => 'user_created',
            'user_email' => $user->user_email,
            'first_name' => get_user_meta($user_id, 'first_name', true),
            'last_name'  => get_user_meta($user_id, 'last_name', true),
            'roles'      =>  $user->roles
        ];
        
        /**
         * Filter the webhook payload before sending user creation notification.
         *
         * @since 1.0.0
         * @param array  $payload The webhook payload data.
         * @param object $user    The user object.
         */
        $payload = apply_filters('hc_oauth2_user_created_webhook_payload', $payload, $user);
        
        /**
         * Fires before sending user creation webhook.
         *
         * @since 1.0.0
         * @param array $payload The webhook payload data.
         * @param int   $user_id The user ID.
         */
        do_action('hc_oauth2_before_user_created_webhook', $payload, $user_id);
        
        $this->send_user_update_webhook($payload);
    }
     
    /**
     * Send user update webhook to configured URL.
     *
     * Sends a POST request with user data to the configured webhook URL.
     * Handles errors and logs responses for debugging.
     *
     * @since 1.0.0
     * @param array $payload The webhook payload data.
     * @return void
     */
    private function send_user_update_webhook($payload) {
        // Get user update webhook URL from options or constants
        $webhook_url = get_option('hc_oauth2_server_user_webhook_url', '');
        
        /**
         * Filter the webhook URL before sending the request.
         *
         * @since 1.0.0
         * @param string $webhook_url The webhook URL.
         * @param array  $payload     The webhook payload data.
         */
        $webhook_url = apply_filters('hc_oauth2_webhook_url', $webhook_url, $payload);
        
        if (empty($webhook_url)) {
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
            error_log('HC-OAuth2-Server: User update webhook URL not configured');
            return;
        }
        
        /**
         * Filter the webhook request arguments before sending.
         *
         * @since 1.0.0
         * @param array $args    The wp_remote_post arguments.
         * @param array $payload The webhook payload data.
         */
        $request_args = apply_filters('hc_oauth2_webhook_request_args', array(
            'headers' => array(
                'Content-Type' => 'application/json',
                'User-Agent' => 'HC-OAuth2-Server/1.0'
            ),
            'body' => wp_json_encode($payload),
            'timeout' => 60,
            'sslverify' => true
        ), $payload);
         
        /**
         * Fires before sending webhook request.
         *
         * @since 1.0.0
         * @param string $webhook_url The webhook URL.
         * @param array  $payload     The webhook payload data.
         * @param array  $request_args The request arguments.
         */
        do_action('hc_oauth2_before_webhook_send', $webhook_url, $payload, $request_args);
        
        // Send POST request
        $response = wp_remote_post($webhook_url, $request_args);
        
        /**
         * Fires after webhook request is sent (regardless of success or failure).
         *
         * @since 1.0.0
         * @param array|WP_Error $response    The response or WP_Error on failure.
         * @param string         $webhook_url The webhook URL.
         * @param array          $payload     The webhook payload data.
         */
        do_action('hc_oauth2_after_webhook_send', $response, $webhook_url, $payload);
         
        // Log the response
        if (is_wp_error($response)) {
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
            error_log('HC-OAuth2-Server: User update webhook failed - ' . $response->get_error_message());
            
            /**
             * Fires when webhook request fails.
             *
             * @since 1.0.0
             * @param WP_Error $error      The error object.
             * @param string   $webhook_url The webhook URL.
             * @param array    $payload     The webhook payload data.
             */
            do_action('hc_oauth2_webhook_error', $response, $webhook_url, $payload);
        } else {
            $response_code = wp_remote_retrieve_response_code($response);
            if ($response_code !== 200) {
                // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
                error_log('HC-OAuth2-Server: User update webhook returned status code ' . $response_code);
            } else {
                /**
                 * Fires when webhook request is successful.
                 *
                 * @since 1.0.0
                 * @param array  $response     The response array.
                 * @param string $webhook_url  The webhook URL.
                 * @param array  $payload      The webhook payload data.
                 */
                do_action('hc_oauth2_webhook_success', $response, $webhook_url, $payload);
            }
        }
     }

}
