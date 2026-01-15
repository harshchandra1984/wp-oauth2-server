# OAuth2 Server for WordPress

A complete OAuth 2.0 authorization server implementation for WordPress. This plugin provides secure authentication and authorization for third-party applications using the authorization code flow with support for access tokens, refresh tokens, user information endpoints, and webhook integrations.

## Description

OAuth2 Server transforms your WordPress site into a fully compliant OAuth 2.0 authorization server, allowing third-party applications to securely authenticate users and access their data. The plugin implements the OAuth 2.0 specification including authorization code flow, token generation, token refresh, user information retrieval, and RP-Initiated Logout (RPLO).

## Features

- **OAuth 2.0 Authorization Code Flow** - Complete implementation of the authorization code grant type
- **Client Management** - Easy-to-use admin interface for managing OAuth2 clients
- **Token Management** - Automatic generation and validation of access and refresh tokens
- **User Information Endpoint** - Retrieve user data via standardized OAuth2 userinfo endpoint
- **RP-Initiated Logout** - Support for logout flows to invalidate tokens
- **Webhook Integration** - Real-time notifications for user profile updates, role changes, and new user registrations
- **WooCommerce Integration** - Seamless integration with WooCommerce login pages
- **Secure Token Storage** - Cryptographically secure token generation and database storage
- **Translation Ready** - Full internationalization support with text domain
- **WordPress Standards Compliant** - Follows WordPress coding standards and best practices

## Requirements

- WordPress 5.0 or higher
- PHP 7.2 or higher
- MySQL 5.6 or higher
- WooCommerce (optional, for enhanced login integration)

## Installation

### Manual Installation

1. Download the plugin zip file or clone the repository
2. Upload the `hc-oauth2-server` folder to `/wp-content/plugins/` directory
3. Activate the plugin through the 'Plugins' menu in WordPress
4. Navigate to **OAuth2 Server** in the WordPress admin menu to configure

### Via WordPress Admin

1. Go to **Plugins > Add New**
2. Click **Upload Plugin**
3. Choose the plugin zip file
4. Click **Install Now**
5. Activate the plugin after installation

## Configuration

### Setting Up OAuth2 Clients

1. Navigate to **OAuth2 Server > Auth Clients** in WordPress admin
2. Click **Add New Client**
3. Enter a descriptive name for your client application
4. Enter the redirect URI where users will be redirected after authorization (multiple URIs can be comma-separated)
5. Click **Add Client**
6. Copy the generated **Client ID** and **Client Secret** - you'll need these in your application

### Webhook Configuration

1. Navigate to **OAuth2 Server > Webhook Settings**
2. Enter your webhook URLs:
   - **Order Webhook URL**: Where order completion notifications will be sent
   - **User Webhook URL**: Where user profile and role change notifications will be sent
3. Click **Save Settings**

## Usage

### OAuth2 Endpoints

The plugin provides the following OAuth2 endpoints:

#### Authorization Endpoint
```
GET /oauth2/authorize
```

**Parameters:**
- `response_type` (required): Must be `code`
- `client_id` (required): Your OAuth2 client ID
- `redirect_uri` (required): The callback URL registered with the client
- `scope` (optional): Space-separated list of requested scopes
- `state` (optional): State parameter for CSRF protection

**Example:**
```
https://yoursite.com/oauth2/authorize?response_type=code&client_id=YOUR_CLIENT_ID&redirect_uri=https://yourapp.com/callback&state=random_state_string
```

#### Token Endpoint
```
POST /oauth2/token
```

**Headers:**
```
Content-Type: application/x-www-form-urlencoded
```

**Parameters (Authorization Code Grant):**
- `grant_type` (required): `authorization_code`
- `code` (required): The authorization code received from the authorization endpoint
- `redirect_uri` (required): Must match the redirect_uri used in authorization request
- `client_id` (required): Your OAuth2 client ID
- `client_secret` (required): Your OAuth2 client secret

**Parameters (Refresh Token Grant):**
- `grant_type` (required): `refresh_token`
- `refresh_token` (required): The refresh token received with the access token
- `client_id` (required): Your OAuth2 client ID
- `client_secret` (required): Your OAuth2 client secret

**Response:**
```json
{
  "access_token": "your_access_token",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "your_refresh_token",
  "scope": "requested_scope"
}
```

#### Userinfo Endpoint
```
GET /oauth2/userinfo
```

**Headers:**
```
Authorization: Bearer YOUR_ACCESS_TOKEN
```

**Response:**
```json
{
  "legacy_id": 123,
  "user_email": "user@example.com",
  "first_name": "John",
  "last_name": "Doe",
  "user_registered": "2024-01-01 00:00:00",
  "roles": "a:1:{s:13:\"administrator\";b:1;}"
}
```

#### Logout Endpoint
```
GET /oauth2/logout
POST /oauth2/logout
```

**Parameters:**
- `access_token` (optional): The access token (can also be sent in Authorization header)
- `client_id` (optional): The client ID for additional validation
- `post_logout_redirect_uri` (optional): Where to redirect after logout
- `state` (optional): State parameter to pass back to client

**Headers:**
```
Authorization: Bearer YOUR_ACCESS_TOKEN
```

### OAuth2 Flow Example

#### 1. Authorization Request

Redirect the user to the authorization endpoint:

```javascript
const authUrl = `https://yoursite.com/oauth2/authorize?` +
  `response_type=code&` +
  `client_id=YOUR_CLIENT_ID&` +
  `redirect_uri=${encodeURIComponent('https://yourapp.com/callback')}&` +
  `state=random_state_string`;

window.location.href = authUrl;
```

#### 2. Handle Authorization Code

In your callback handler:

```javascript
// Extract the authorization code from the callback URL
const urlParams = new URLSearchParams(window.location.search);
const code = urlParams.get('code');
const state = urlParams.get('state');

// Verify state matches the one you sent
if (state !== expectedState) {
  // Handle error
}

// Exchange code for tokens
fetch('https://yoursite.com/oauth2/token', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/x-www-form-urlencoded',
  },
  body: new URLSearchParams({
    grant_type: 'authorization_code',
    code: code,
    redirect_uri: 'https://yourapp.com/callback',
    client_id: 'YOUR_CLIENT_ID',
    client_secret: 'YOUR_CLIENT_SECRET'
  })
})
.then(response => response.json())
.then(data => {
  // Store access_token and refresh_token
  const accessToken = data.access_token;
  const refreshToken = data.refresh_token;
});
```

#### 3. Use Access Token

```javascript
// Make authenticated requests
fetch('https://yoursite.com/oauth2/userinfo', {
  headers: {
    'Authorization': `Bearer ${accessToken}`
  }
})
.then(response => response.json())
.then(userInfo => {
  // Use user information
});
```

#### 4. Refresh Access Token

When the access token expires:

```javascript
fetch('https://yoursite.com/oauth2/token', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/x-www-form-urlencoded',
  },
  body: new URLSearchParams({
    grant_type: 'refresh_token',
    refresh_token: refreshToken,
    client_id: 'YOUR_CLIENT_ID',
    client_secret: 'YOUR_CLIENT_SECRET'
  })
})
.then(response => response.json())
.then(data => {
  // Update access_token and refresh_token
  const newAccessToken = data.access_token;
  const newRefreshToken = data.refresh_token;
});
```

## Webhooks

The plugin can send webhook notifications for the following events:

### User Profile Update

Triggered when a user profile is updated.

**Payload:**
```json
{
  "wp_id": 123,
  "event_type": "profile_update",
  "user_email": "user@example.com",
  "first_name": "John",
  "last_name": "Doe",
  "roles": ["administrator"]
}
```

### User Role Change

Triggered when a user's role is changed.

**Payload:**
```json
{
  "wp_id": 123,
  "event_type": "role_change",
  "user_email": "user@example.com",
  "first_name": "John",
  "last_name": "Doe",
  "roles": ["subscriber"]
}
```

### User Created

Triggered when a new user is registered.

**Payload:**
```json
{
  "wp_id": 123,
  "event_type": "user_created",
  "user_email": "user@example.com",
  "first_name": "John",
  "last_name": "Doe",
  "roles": ["subscriber"]
}
```

### Webhook Request Format

- **Method**: POST
- **Content-Type**: application/json
- **User-Agent**: HC-OAuth2-Server/1.0
- **Timeout**: 60 seconds
- **SSL Verification**: Enabled

## Admin Interface

### Main Dashboard

View server information, endpoints, and quick statistics:
- Authorization Endpoint URL
- Token Endpoint URL
- Userinfo Endpoint URL
- Logout Endpoint URL
- Registered Clients Count
- Active Tokens Count

### Client Management

- **Add Clients**: Create new OAuth2 client applications
- **View Clients**: List all registered clients with their credentials
- **Regenerate Secrets**: Generate new client secrets when needed
- **Delete Clients**: Remove clients and their associated tokens

### Token Management

- **View Tokens**: List all access tokens with user information
- **Token Status**: See which tokens are active or expired
- **Revoke Tokens**: Invalidate access tokens manually

## Security Features

- **Cryptographically Secure Tokens**: Uses `random_bytes()` for secure token generation
- **Token Expiration**: Access tokens expire after 1 hour, authorization codes after 10 minutes
- **Client Secret Protection**: Secure storage and validation of client credentials
- **Redirect URI Validation**: Ensures tokens are only issued to registered redirect URIs
- **Nonce Verification**: All admin actions are protected with WordPress nonces
- **Input Sanitization**: All user inputs are sanitized and validated
- **SQL Injection Prevention**: All database queries use prepared statements
- **XSS Protection**: All output is properly escaped

## Database Schema

The plugin creates the following database tables:

### `wp_oauth2_clients`
Stores registered OAuth2 client applications.

### `wp_oauth2_codes`
Stores temporary authorization codes (expires after 10 minutes).

### `wp_oauth2_tokens`
Stores access tokens and refresh tokens.

## Error Handling

### OAuth2 Error Responses

The plugin returns standard OAuth2 error responses:

- `invalid_request`: Missing or malformed request parameters
- `unauthorized_client`: Invalid client credentials
- `invalid_client`: Client authentication failed
- `invalid_grant`: Invalid authorization code or refresh token
- `unsupported_response_type`: Only `code` response type is supported
- `unsupported_grant_type`: Only `authorization_code` and `refresh_token` grant types are supported
- `invalid_token`: Invalid or expired access token
- `server_error`: Internal server error

## Troubleshooting

### Authorization Code Not Working

- Verify the redirect URI matches exactly (including trailing slashes)
- Check that the client_id is correct
- Ensure the authorization code hasn't expired (10 minutes)

### Token Request Failing

- Verify client_id and client_secret are correct
- Ensure the authorization code matches the redirect_uri used in authorization
- Check that the authorization code hasn't been used before (codes are single-use)

### Userinfo Endpoint Returns 401

- Verify the access token is valid and not expired
- Ensure the Authorization header format is correct: `Bearer TOKEN`
- Check that the token exists in the database and hasn't been revoked

### Webhooks Not Firing

- Verify webhook URLs are configured in admin settings
- Check that the webhook URL is accessible from your WordPress server
- Review WordPress error logs for webhook delivery failures
- Ensure SSL verification is properly configured

## Developer Hooks

The plugin provides extensive WordPress hooks for developers to extend functionality. For a complete reference of all available hooks, see [HOOKS.md](HOOKS.md).

### Key Hooks Overview

**Action Hooks:**
- `hc_oauth2_before_authorize`: Fires before processing authorization request
- `hc_oauth2_after_authorize`: Fires after authorization code is generated
- `hc_oauth2_before_token_issue`: Fires before issuing access token
- `hc_oauth2_after_token_issue`: Fires after access token is issued
- `hc_oauth2_before_token_refresh`: Fires before refreshing access token
- `hc_oauth2_after_token_refresh`: Fires after access token is refreshed
- `hc_oauth2_before_client_create`: Fires before creating a new client
- `hc_oauth2_after_client_create`: Fires after client is created
- `hc_oauth2_before_webhook_send`: Fires before sending webhook
- `hc_oauth2_after_webhook_send`: Fires after webhook is sent

**Filter Hooks:**
- `hc_oauth2_token_expires_in`: Filter the access token expiration time (default: 3600 seconds)
- `hc_oauth2_authorization_code_expires_in`: Filter authorization code expiration time (default: 600 seconds)
- `hc_oauth2_userinfo_data`: Filter user information returned by userinfo endpoint
- `hc_oauth2_token_data`: Filter token data before returning to client
- `hc_oauth2_client_create_data`: Filter client data before creation
- `hc_oauth2_webhook_payload`: Filter webhook payload data
- `hc_oauth2_webhook_url`: Filter webhook URL
- `hc_oauth2_webhook_request_args`: Filter webhook request arguments

See [HOOKS.md](HOOKS.md) for complete documentation with examples.

## Translation

The plugin is fully translation-ready. Translation files should be placed in:
```
wp-content/plugins/hc-oauth2-server/languages/
```

Text domain: `hc-oauth2-server`

## Changelog

### 1.0.0
- Initial release
- OAuth 2.0 authorization code flow implementation
- Client management interface
- Token generation and validation
- User information endpoint
- RP-Initiated Logout support
- Webhook integration for user events
- WooCommerce integration
- Full translation support
- WordPress coding standards compliance

## Support

For support, bug reports, and feature requests, please visit:
- Plugin URI: https://larawizard.hashnode.dev/
- Author URI: https://larawizard.hashnode.dev/

## License

This plugin is licensed under the GPL v2 or later.

```
Copyright (C) 2026 Harsh Chandra

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
```

## Credits

Developed by Harsh Chandra

For more information, visit: https://larawizard.hashnode.dev/
