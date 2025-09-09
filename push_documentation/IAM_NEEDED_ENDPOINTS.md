# Push Authentication API Documentation

This document describes the external push authentication endpoints that needs to be implemented on IAM service to fully integrated into push otp.

## Endpoints

### 1. Submit Push Registration

**Endpoint:** `POST /submit`

**Description:** Registers a new push authentication device for the user. This endpoint is used during the initial setup of push authentication.

**Request Body:**

```json
{
  "deviceName": "iPhone 15",
  "pushId": "device-push-token-12345",
  "deviceKeyId": "device-key-identifier-abc123",
  "encodedSecret": "JBSWY3DPEHPK3PXP",
  "deviceType": "IOS",
  "initialCode": "123456"
}
```

**Field Descriptions:**

- `deviceName` (string, required): Human-readable name for the device (e.g., "iPhone 15", "Samsung Galaxy")
- `pushId` (string, required): Unique push notification token/identifier for the device
- `deviceKeyId` (string, required): Unique identifier for the device secret key
- `encodedSecret` (string, required): Base32-encoded secret for OTP generation
- `deviceType` (enum, required): Device platform - either "IOS" or "ANDROID"
- `initialCode` (string, required): Initial OTP code for verification during registration

**Response:**

- **204 No Content**: Registration successful
- **400 Bad Request**: Invalid or missing data fields
- **403 Forbidden**: Registration not started or invalid secret code

---

### 2. Validate Push Authentication

**Endpoint:** `POST /validate`

**Description:** Validates a push authentication challenge response. This endpoint is called when the user responds to a push notification challenge.

**Request Body:**

```json
{
  "pushId": "device-push-token-12345",
  "otp": "654321",
  "challengeResponse": "user-response-to-challenge"
}
```

**Field Descriptions:**

- `pushId` (string, required): The push notification token/identifier for the device
- `otp` (string, required): One-time password for verification
- `challengeResponse` (string, required): User's response to the authentication challenge(number(CHALLENGE_CHOOSE,CHALLENGE_WRITE)/true(CHALLENGE_APPROVE))

**Response:**

- **204 No Content**: Validation successful
- **400 Bad Request**: Invalid or missing data fields
- **403 Forbidden**: Invalid OTP or challenge response
---

### 3. Terminate Push Authentication

**Endpoint:** `POST /terminate`

**Description:** Terminates an active push authentication session. This endpoint is used to cancel or end a push authentication process.

**Request Body:**

```json
{
  "pushId": "device-push-token-12345",
  "otp": "654321"
}
```

**Field Descriptions:**

- `pushId` (string, required): The push notification token/identifier for the device
- `otp` (string, required): One-time password for verification

**Response:**

- **204 No Content**: Termination successful
- **400 Bad Request**: Invalid or missing data fields, device not found
- **403 Forbidden**: Invalid OTP
---

### 4. Change Push ID

**Endpoint:** `POST /push-id-change`

**Description:** Updates the push ID for an existing device. This is useful when the device's push notification token changes (e.g., after app reinstall or device change).

**Request Body:**

```json
{
  "deviceKey": "device-key-identifier-abc123",
  "pushId": "new-device-push-token-67890",
  "otp": "654321"
}
```

**Field Descriptions:**

- `deviceKey` (string, required): The device key identifier to identify the device
- `pushId` (string, required): New push notification token/identifier for the device
- `otp` (string, required): One-time password for verification

**Response:**

- **204 No Content**: Push ID change successful
- **400 Bad Request**: Invalid or missing data fields, device not found
- **403 Forbidden**: Invalid OTP

---

## Error Responses

All endpoints may return the following error responses:

### 400 Bad Request

```json
{
  "error": "one or more data field for push [operation] are blank"
}
```

### 403 Forbidden

```json
{
  "error": "otp registration data is invalid"
}
```

### 500 Internal Server Error

```json
{
  "error": "Internal server error"
}
```

## Device Types

The `deviceType` field accepts the following values:

- `IOS`: Apple iOS devices
- `ANDROID`: Google Android devices

## Notes

1. **Authentication Required**: All endpoints require valid otp tokens
2. **User Scoping**: All operations are scoped to the authenticated user
3. **OTP Validation**: All endpoints that require OTP validation use the same OTP mechanism
4. **Push ID Management**: Push IDs should be unique per device and may change over time
5. **Device Registration**: Devices must be registered before they can be used for authentication

## Integration Flow

1. **Registration**: Use `/submit` to register a new device
2. **Authentication**: System sends push notifications, user responds via `/validate` or `/terminate`
3. **Management**: `/push-id-change` to update device tokens
