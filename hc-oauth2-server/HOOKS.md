# WordPress Hooks Reference

This document provides a complete reference of all WordPress action and filter hooks available in the OAuth2 Server plugin for extending functionality.

## Table of Contents

- [Action Hooks](#action-hooks)
- [Filter Hooks](#filter-hooks)
- [Hook Examples](#hook-examples)

## Action Hooks

Action hooks allow you to execute custom code at specific points in the OAuth2 flow.

### Authorization Flow

#### `hc_oauth2_before_authorize`
Fires before processing an OAuth2 authorization request.

**Parameters:**
- `$response_type` (string) - The response type requested
- `$client_id` (string) - The client ID
- `$redirect_uri` (string) - The redirect URI
- `$scope` (string) - The requested scope
- `$state` (string) - The state parameter

**Example:**
```php
add_action('hc_oauth2_before_authorize', function($response_type, $client_id, $redirect_uri, $scope, $state) {
    // Log authorization attempts
    error_log("Authorization requested for client: $client_id");
}, 10, 5);
```

#### `hc_oauth2_after_authorize`
Fires after an authorization code is successfully generated.

**Parameters:**
- `$code` (string) - The generated authorization code
- `$client_id` (string) - The client ID
- `$user_id` (int) - The user ID
- `$redirect_uri` (string) - The redirect URI
- `$scope` (string) - The requested scope

**Example:**
```php
add_action('hc_oauth2_after_authorize', function($code, $client_id, $user_id, $redirect_uri, $scope) {
    // Send notification email
    wp_mail(get_option('admin_email'), 'New OAuth2 Authorization', "User $user_id authorized client $client_id");
}, 10, 5);
```

### Token Flow

#### `hc_oauth2_before_token_issue`
Fires before issuing an access token from an authorization code.

**Parameters:**
- `$auth_code` (object) - The authorization code object
- `$client` (object) - The client object

**Example:**
```php
add_action('hc_oauth2_before_token_issue', function($auth_code, $client) {
    // Additional validation or logging
    if (!is_token_allowed_for_user($auth_code->user_id)) {
        wp_die('Token issuance not allowed');
    }
}, 10, 2);
```

#### `hc_oauth2_after_token_issue`
Fires after an access token is successfully issued.

**Parameters:**
- `$token_data` (array) - The token data array
- `$auth_code` (object) - The authorization code object
- `$client` (object) - The client object

**Example:**
```php
add_action('hc_oauth2_after_token_issue', function($token_data, $auth_code, $client) {
    // Log token issuance
    log_token_activity('issued', $token_data['access_token'], $auth_code->user_id);
}, 10, 3);
```

#### `hc_oauth2_before_token_refresh`
Fires before refreshing an access token.

**Parameters:**
- `$token` (object) - The refresh token object
- `$client` (object) - The client object

**Example:**
```php
add_action('hc_oauth2_before_token_refresh', function($token, $client) {
    // Rate limiting check
    check_refresh_rate_limit($token->user_id);
}, 10, 2);
```

#### `hc_oauth2_after_token_refresh`
Fires after an access token is successfully refreshed.

**Parameters:**
- `$token_data` (array) - The new token data array
- `$old_token` (object) - The old token object
- `$client` (object) - The client object

**Example:**
```php
add_action('hc_oauth2_after_token_refresh', function($token_data, $old_token, $client) {
    // Update token usage analytics
    update_token_analytics($old_token->access_token, $token_data['access_token']);
}, 10, 3);
```

#### `hc_oauth2_before_token_revoke`
Fires before revoking tokens during logout.

**Parameters:**
- `$user_id` (int) - The user ID
- `$client_id` (string) - The client ID (may be empty)

**Example:**
```php
add_action('hc_oauth2_before_token_revoke', function($user_id, $client_id) {
    // Log token revocation
    log_security_event('token_revoked', $user_id, $client_id);
}, 10, 2);
```

#### `hc_oauth2_after_token_revoke`
Fires after tokens are revoked during logout.

**Parameters:**
- `$user_id` (int) - The user ID
- `$client_id` (string) - The client ID (may be empty)

**Example:**
```php
add_action('hc_oauth2_after_token_revoke', function($user_id, $client_id) {
    // Clear user sessions in other systems
    clear_external_sessions($user_id);
}, 10, 2);
```

#### `hc_oauth2_before_admin_token_revoke`
Fires before revoking an access token from the admin interface.

**Parameters:**
- `$access_token` (string) - The access token to revoke

**Example:**
```php
add_action('hc_oauth2_before_admin_token_revoke', function($access_token) {
    // Notify user about token revocation
    $token = get_token_by_access_token($access_token);
    if ($token) {
        send_revocation_email($token->user_id, $access_token);
    }
}, 10, 1);
```

#### `hc_oauth2_after_admin_token_revoke`
Fires after an access token is successfully revoked from the admin interface.

**Parameters:**
- `$access_token` (string) - The revoked access token

**Example:**
```php
add_action('hc_oauth2_after_admin_token_revoke', function($access_token) {
    // Audit log entry
    write_audit_log('admin_token_revoked', $access_token, get_current_user_id());
}, 10, 1);
```

#### `hc_oauth2_before_userinfo`
Fires before returning user information via the userinfo endpoint.

**Parameters:**
- `$user_info` (array) - The user information array
- `$token` (object) - The token object

**Example:**
```php
add_action('hc_oauth2_before_userinfo', function($user_info, $token) {
    // Track userinfo access
    track_userinfo_access($user_info['legacy_id'], $token->client_id);
}, 10, 2);
```

### Client Management

#### `hc_oauth2_before_client_create`
Fires before creating a new OAuth2 client.

**Parameters:**
- `$client_id` (string) - The client ID
- `$client_secret` (string) - The client secret
- `$name` (string) - The client name
- `$redirect_uri` (string) - The redirect URI

**Example:**
```php
add_action('hc_oauth2_before_client_create', function($client_id, $client_secret, $name, $redirect_uri) {
    // Validate redirect URI against allowed domains
    validate_client_redirect_uri($redirect_uri);
}, 10, 4);
```

#### `hc_oauth2_after_client_create`
Fires after a new OAuth2 client is successfully created.

**Parameters:**
- `$client_id` (string) - The client ID
- `$client_secret` (string) - The client secret
- `$name` (string) - The client name
- `$redirect_uri` (string) - The redirect URI

**Example:**
```php
add_action('hc_oauth2_after_client_create', function($client_id, $client_secret, $name, $redirect_uri) {
    // Send welcome email with credentials
    send_client_credentials_email(get_option('admin_email'), $client_id, $client_secret);
}, 10, 4);
```

#### `hc_oauth2_before_client_delete`
Fires before deleting an OAuth2 client.

**Parameters:**
- `$client_id` (string) - The client ID to delete

**Example:**
```php
add_action('hc_oauth2_before_client_delete', function($client_id) {
    // Backup client data before deletion
    backup_client_data($client_id);
}, 10, 1);
```

#### `hc_oauth2_after_client_delete`
Fires after an OAuth2 client is successfully deleted.

**Parameters:**
- `$client_id` (string) - The deleted client ID

**Example:**
```php
add_action('hc_oauth2_after_client_delete', function($client_id) {
    // Clean up related data
    cleanup_client_resources($client_id);
}, 10, 1);
```

#### `hc_oauth2_before_secret_regenerate`
Fires before regenerating a client secret.

**Parameters:**
- `$client_id` (string) - The client ID
- `$new_secret` (string) - The new secret that will be set

**Example:**
```php
add_action('hc_oauth2_before_secret_regenerate', function($client_id, $new_secret) {
    // Log secret regeneration
    log_security_event('secret_regenerated', $client_id, get_current_user_id());
}, 10, 2);
```

#### `hc_oauth2_after_secret_regenerate`
Fires after a client secret is successfully regenerated.

**Parameters:**
- `$client_id` (string) - The client ID
- `$new_secret` (string) - The new secret

**Example:**
```php
add_action('hc_oauth2_after_secret_regenerate', function($client_id, $new_secret) {
    // Notify client owner
    notify_client_secret_change($client_id, $new_secret);
}, 10, 2);
```

### Database

#### `hc_oauth2_before_create_tables`
Fires before creating OAuth2 database tables.

**Example:**
```php
add_action('hc_oauth2_before_create_tables', function() {
    // Perform pre-installation checks
    check_database_permissions();
}, 10);
```

#### `hc_oauth2_after_create_tables`
Fires after OAuth2 database tables are created.

**Example:**
```php
add_action('hc_oauth2_after_create_tables', function() {
    // Seed default data
    seed_default_oauth2_data();
}, 10);
```

### Webhooks

#### `hc_oauth2_before_profile_update_webhook`
Fires before sending a profile update webhook.

**Parameters:**
- `$payload` (array) - The webhook payload data
- `$user_id` (int) - The user ID

**Example:**
```php
add_action('hc_oauth2_before_profile_update_webhook', function($payload, $user_id) {
    // Add custom data to webhook
    $payload['custom_field'] = get_user_meta($user_id, 'custom_field', true);
}, 10, 2);
```

#### `hc_oauth2_before_role_change_webhook`
Fires before sending a role change webhook.

**Parameters:**
- `$payload` (array) - The webhook payload data
- `$user_id` (int) - The user ID

**Example:**
```php
add_action('hc_oauth2_before_role_change_webhook', function($payload, $user_id) {
    // Log role changes
    log_role_change($user_id, $payload['roles']);
}, 10, 2);
```

#### `hc_oauth2_before_user_created_webhook`
Fires before sending a user creation webhook.

**Parameters:**
- `$payload` (array) - The webhook payload data
- `$user_id` (int) - The user ID

**Example:**
```php
add_action('hc_oauth2_before_user_created_webhook', function($payload, $user_id) {
    // Send welcome email
    send_welcome_email($payload['user_email']);
}, 10, 2);
```

#### `hc_oauth2_before_webhook_send`
Fires before sending any webhook request.

**Parameters:**
- `$webhook_url` (string) - The webhook URL
- `$payload` (array) - The webhook payload data
- `$request_args` (array) - The request arguments

**Example:**
```php
add_action('hc_oauth2_before_webhook_send', function($webhook_url, $payload, $request_args) {
    // Rate limiting
    if (!check_webhook_rate_limit($webhook_url)) {
        // Cancel webhook by modifying request args
        return false;
    }
}, 10, 3);
```

#### `hc_oauth2_after_webhook_send`
Fires after a webhook request is sent (regardless of success or failure).

**Parameters:**
- `$response` (array|WP_Error) - The response or WP_Error on failure
- `$webhook_url` (string) - The webhook URL
- `$payload` (array) - The webhook payload data

**Example:**
```php
add_action('hc_oauth2_after_webhook_send', function($response, $webhook_url, $payload) {
    // Log webhook attempt
    log_webhook_attempt($webhook_url, is_wp_error($response), $payload);
}, 10, 3);
```

#### `hc_oauth2_webhook_success`
Fires when a webhook request is successful (HTTP 200).

**Parameters:**
- `$response` (array) - The response array
- `$webhook_url` (string) - The webhook URL
- `$payload` (array) - The webhook payload data

**Example:**
```php
add_action('hc_oauth2_webhook_success', function($response, $webhook_url, $payload) {
    // Update webhook delivery status
    mark_webhook_delivered($webhook_url, $payload['wp_id']);
}, 10, 3);
```

#### `hc_oauth2_webhook_error`
Fires when a webhook request fails.

**Parameters:**
- `$error` (WP_Error) - The error object
- `$webhook_url` (string) - The webhook URL
- `$payload` (array) - The webhook payload data

**Example:**
```php
add_action('hc_oauth2_webhook_error', function($error, $webhook_url, $payload) {
    // Queue webhook for retry
    queue_webhook_retry($webhook_url, $payload);
}, 10, 3);
```

## Filter Hooks

Filter hooks allow you to modify data before it's used or returned.

### Authorization Flow

#### `hc_oauth2_login_url`
Filter the login URL for OAuth2 authorization flow.

**Parameters:**
- `$login_url` (string) - The login URL
- `$client_id` (string) - The client ID
- `$redirect_uri` (string) - The redirect URI

**Returns:** (string) Modified login URL

**Example:**
```php
add_filter('hc_oauth2_login_url', function($login_url, $client_id, $redirect_uri) {
    // Use custom login page for specific clients
    if ($client_id === 'special-client-id') {
        return home_url('/custom-login');
    }
    return $login_url;
}, 10, 3);
```

#### `hc_oauth2_authorization_redirect_url`
Filter the redirect URL after authorization.

**Parameters:**
- `$redirect_url` (string) - The redirect URL
- `$code` (string) - The authorization code
- `$state` (string) - The state parameter
- `$redirect_uri` (string) - The original redirect URI

**Returns:** (string) Modified redirect URL

**Example:**
```php
add_filter('hc_oauth2_authorization_redirect_url', function($redirect_url, $code, $state, $redirect_uri) {
    // Add tracking parameter
    return add_query_arg('source', 'oauth2', $redirect_url);
}, 10, 4);
```

### Token Flow

#### `hc_oauth2_token_expires_in`
Filter the access token expiration time in seconds.

**Parameters:**
- `$expires_in` (int) - Expiration time in seconds. Default 3600 (1 hour)
- `$user_id` (int) - The user ID
- `$client_id` (string) - The client ID
- `$scope` (string) - The requested scope

**Returns:** (int) Modified expiration time in seconds

**Example:**
```php
add_filter('hc_oauth2_token_expires_in', function($expires_in, $user_id, $client_id, $scope) {
    // Extended expiration for premium users
    if (user_has_premium_access($user_id)) {
        return 86400; // 24 hours
    }
    return $expires_in;
}, 10, 4);
```

#### `hc_oauth2_authorization_code_expires_in`
Filter the authorization code expiration time in seconds.

**Parameters:**
- `$expires_in` (int) - Expiration time in seconds. Default 600 (10 minutes)
- `$client_id` (string) - The client ID
- `$user_id` (int) - The user ID

**Returns:** (int) Modified expiration time in seconds

**Example:**
```php
add_filter('hc_oauth2_authorization_code_expires_in', function($expires_in, $client_id, $user_id) {
    // Shorter expiration for high-security clients
    if (is_high_security_client($client_id)) {
        return 300; // 5 minutes
    }
    return $expires_in;
}, 10, 3);
```

#### `hc_oauth2_token_data`
Filter the token data before returning to client.

**Parameters:**
- `$token_data` (array) - The token data array
- `$auth_code` (object) - The authorization code object
- `$client` (object) - The client object

**Returns:** (array) Modified token data array

**Example:**
```php
add_filter('hc_oauth2_token_data', function($token_data, $auth_code, $client) {
    // Add custom fields to token response
    $token_data['custom_field'] = get_custom_user_data($auth_code->user_id);
    return $token_data;
}, 10, 3);
```

#### `hc_oauth2_refresh_token_data`
Filter the refreshed token data before returning to client.

**Parameters:**
- `$token_data` (array) - The new token data array
- `$old_token` (object) - The old token object
- `$client` (object) - The client object

**Returns:** (array) Modified token data array

**Example:**
```php
add_filter('hc_oauth2_refresh_token_data', function($token_data, $old_token, $client) {
    // Maintain custom data across refreshes
    $token_data['session_id'] = get_token_session_id($old_token->access_token);
    return $token_data;
}, 10, 3);
```

#### `hc_oauth2_access_token_data`
Filter the access token data before storing in database.

**Parameters:**
- `$token_data` (array) - The token data array
- `$user_id` (int) - The user ID
- `$client_id` (string) - The client ID
- `$scope` (string) - The requested scope

**Returns:** (array) Modified token data array

**Example:**
```php
add_filter('hc_oauth2_access_token_data', function($token_data, $user_id, $client_id, $scope) {
    // Add metadata to token
    $token_data['issued_at'] = time();
    $token_data['ip_address'] = $_SERVER['REMOTE_ADDR'];
    return $token_data;
}, 10, 4);
```

#### `hc_oauth2_userinfo_data`
Filter the user information returned by the userinfo endpoint.

**Parameters:**
- `$user_info` (array) - The user information array
- `$token` (object) - The token object

**Returns:** (array) Modified user information array

**Example:**
```php
add_filter('hc_oauth2_userinfo_data', function($user_info, $token) {
    // Add additional user fields
    $user_info['display_name'] = get_userdata($user_info['legacy_id'])->display_name;
    $user_info['avatar_url'] = get_avatar_url($user_info['legacy_id']);
    
    // Remove sensitive data based on scope
    if (!has_scope_permission($token->scope, 'email')) {
        unset($user_info['user_email']);
    }
    
    return $user_info;
}, 10, 2);
```

### Client Management

#### `hc_oauth2_client_create_data`
Filter the client data before inserting into database.

**Parameters:**
- `$client_data` (array) - Array containing name and redirect_uri

**Returns:** (array) Modified client data array

**Example:**
```php
add_filter('hc_oauth2_client_create_data', function($client_data) {
    // Auto-append allowed domain
    $client_data['redirect_uri'] = sanitize_redirect_uri($client_data['redirect_uri']);
    return $client_data;
}, 10, 1);
```

#### `hc_oauth2_client_id`
Filter the generated client ID.

**Parameters:**
- `$client_id` (string) - The generated client ID
- `$name` (string) - The client name

**Returns:** (string) Modified client ID

**Example:**
```php
add_filter('hc_oauth2_client_id', function($client_id, $name) {
    // Use custom ID format
    return 'custom_prefix_' . $client_id;
}, 10, 2);
```

#### `hc_oauth2_client_secret`
Filter the generated client secret.

**Parameters:**
- `$client_secret` (string) - The generated client secret
- `$name` (string) - The client name

**Returns:** (string) Modified client secret

**Example:**
```php
add_filter('hc_oauth2_client_secret', function($client_secret, $name) {
    // Enforce minimum length
    if (strlen($client_secret) < 40) {
        $client_secret = str_repeat($client_secret, 2);
    }
    return $client_secret;
}, 10, 2);
```

#### `hc_oauth2_regenerate_client_secret`
Filter the new client secret before regenerating.

**Parameters:**
- `$new_secret` (string) - The generated new secret
- `$client_id` (string) - The client ID

**Returns:** (string) Modified new secret

**Example:**
```php
add_filter('hc_oauth2_regenerate_client_secret', function($new_secret, $client_id) {
    // Ensure secret meets complexity requirements
    return enforce_secret_complexity($new_secret);
}, 10, 2);
```

#### `hc_oauth2_validate_client`
Filter the validated client object.

**Parameters:**
- `$client` (object|false) - The client object or false if not found
- `$client_id` (string) - The client ID
- `$client_secret` (string|null) - The client secret (null if not provided)

**Returns:** (object|false) Modified client object

**Example:**
```php
add_filter('hc_oauth2_validate_client', function($client, $client_id, $client_secret) {
    // Additional validation logic
    if ($client && !is_client_active($client_id)) {
        return false; // Reject inactive clients
    }
    return $client;
}, 10, 3);
```

#### `hc_oauth2_validate_redirect_uri`
Filter the redirect URI validation result.

**Parameters:**
- `$is_valid` (bool) - Whether the redirect URI is valid
- `$client_id` (string) - The client ID
- `$redirect_uri` (string) - The redirect URI being validated
- `$allowed_uris` (array) - Array of allowed redirect URIs

**Returns:** (bool) Modified validation result

**Example:**
```php
add_filter('hc_oauth2_validate_redirect_uri', function($is_valid, $client_id, $redirect_uri, $allowed_uris) {
    // Allow localhost for development
    if (strpos($redirect_uri, 'localhost') !== false && WP_DEBUG) {
        return true;
    }
    return $is_valid;
}, 10, 4);
```

### Webhooks

#### `hc_oauth2_profile_update_webhook_payload`
Filter the webhook payload before sending profile update notification.

**Parameters:**
- `$payload` (array) - The webhook payload data
- `$user` (object) - The user object
- `$old_user_data` (object) - The previous user data

**Returns:** (array) Modified payload array

**Example:**
```php
add_filter('hc_oauth2_profile_update_webhook_payload', function($payload, $user, $old_user_data) {
    // Add changed fields
    $payload['changed_fields'] = get_changed_fields($user, $old_user_data);
    return $payload;
}, 10, 3);
```

#### `hc_oauth2_role_change_webhook_payload`
Filter the webhook payload before sending role change notification.

**Parameters:**
- `$payload` (array) - The webhook payload data
- `$user` (object) - The user object
- `$meta_key` (string) - The meta key that was updated
- `$meta_value` (mixed) - The new meta value (roles)

**Returns:** (array) Modified payload array

**Example:**
```php
add_filter('hc_oauth2_role_change_webhook_payload', function($payload, $user, $meta_key, $meta_value) {
    // Add previous roles
    $payload['previous_roles'] = get_user_meta($user->ID, 'previous_roles', true);
    return $payload;
}, 10, 4);
```

#### `hc_oauth2_user_created_webhook_payload`
Filter the webhook payload before sending user creation notification.

**Parameters:**
- `$payload` (array) - The webhook payload data
- `$user` (object) - The user object

**Returns:** (array) Modified payload array

**Example:**
```php
add_filter('hc_oauth2_user_created_webhook_payload', function($payload, $user) {
    // Add registration source
    $payload['registration_source'] = get_user_meta($user->ID, 'registration_source', true);
    return $payload;
}, 10, 2);
```

#### `hc_oauth2_webhook_url`
Filter the webhook URL before sending the request.

**Parameters:**
- `$webhook_url` (string) - The webhook URL
- `$payload` (array) - The webhook payload data

**Returns:** (string) Modified webhook URL

**Example:**
```php
add_filter('hc_oauth2_webhook_url', function($webhook_url, $payload) {
    // Use different webhook URL based on event type
    if ($payload['event_type'] === 'user_created') {
        return get_option('custom_user_webhook_url');
    }
    return $webhook_url;
}, 10, 2);
```

#### `hc_oauth2_webhook_request_args`
Filter the webhook request arguments before sending.

**Parameters:**
- `$args` (array) - The wp_remote_post arguments
- `$payload` (array) - The webhook payload data

**Returns:** (array) Modified request arguments

**Example:**
```php
add_filter('hc_oauth2_webhook_request_args', function($args, $payload) {
    // Add custom headers
    $args['headers']['X-API-Key'] = get_option('webhook_api_key');
    $args['headers']['X-Event-Type'] = $payload['event_type'];
    
    // Add authentication
    $args['headers']['Authorization'] = 'Bearer ' . generate_webhook_token($payload);
    
    return $args;
}, 10, 2);
```

## Hook Examples

### Complete Example: Custom Token Expiration

```php
/**
 * Set custom token expiration based on user role
 */
add_filter('hc_oauth2_token_expires_in', function($expires_in, $user_id, $client_id, $scope) {
    $user = get_userdata($user_id);
    
    if (in_array('administrator', $user->roles)) {
        return 7200; // 2 hours for admins
    } elseif (in_array('premium_member', $user->roles)) {
        return 5400; // 1.5 hours for premium
    }
    
    return $expires_in; // Default 1 hour
}, 10, 4);
```

### Complete Example: Enhanced User Info

```php
/**
 * Add additional fields to userinfo endpoint
 */
add_filter('hc_oauth2_userinfo_data', function($user_info, $token) {
    $user_id = $user_info['legacy_id'];
    
    // Add billing information if scope allows
    if (has_scope_permission($token->scope, 'billing')) {
        $user_info['billing_address'] = get_user_meta($user_id, 'billing_address', true);
        $user_info['billing_city'] = get_user_meta($user_id, 'billing_city', true);
    }
    
    // Add profile picture
    $user_info['avatar_url'] = get_avatar_url($user_id, array('size' => 200));
    
    return $user_info;
}, 10, 2);
```

### Complete Example: Webhook Logging

```php
/**
 * Log all webhook attempts to custom database table
 */
add_action('hc_oauth2_after_webhook_send', function($response, $webhook_url, $payload) {
    global $wpdb;
    $table = $wpdb->prefix . 'oauth2_webhook_logs';
    
    $wpdb->insert($table, array(
        'webhook_url' => $webhook_url,
        'event_type' => $payload['event_type'],
        'payload' => wp_json_encode($payload),
        'status_code' => is_wp_error($response) ? 0 : wp_remote_retrieve_response_code($response),
        'success' => !is_wp_error($response) && wp_remote_retrieve_response_code($response) === 200,
        'created_at' => current_time('mysql')
    ));
}, 10, 3);
```

## Hook Priority

All hooks use the default priority of 10. You can change the priority when adding your hooks:

```php
// High priority (runs early)
add_action('hc_oauth2_before_authorize', 'my_function', 5);

// Low priority (runs late)
add_filter('hc_oauth2_token_data', 'my_function', 20);
```

## Best Practices

1. **Always return the filtered value** - When using filters, always return the modified value
2. **Validate input** - Always validate and sanitize data in your hook callbacks
3. **Check conditions** - Verify conditions before modifying data
4. **Log important actions** - Use action hooks to log security events
5. **Don't break the flow** - Avoid using `wp_die()` or `exit()` in filters unless absolutely necessary
6. **Document your hooks** - Document any custom hooks you create in your extension

## Support

For questions about hooks or extending the plugin, visit:
- Plugin URI: https://larawizard.hashnode.dev/
- Author URI: https://larawizard.hashnode.dev/
