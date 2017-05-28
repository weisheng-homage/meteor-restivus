class @OAuth2
  constructor: (options) ->
    @_models = options.oauth2Model

  auth: (endpointContext) ->
    bearer = endpointContext.request.headers.authorization
    if bearer && bearer.startsWith("Bearer ")
      bearerToken = bearer.substr("Bearer ".length )
      token = @checkBearer bearerToken
      if token
        endpointContext.request.oauth2 = token
        return {success: true}
      else
        # Token not found or expired
        {
          data: {
            statusCode: 403,
            body: {
              error: 'forbidden',
              error_description: 'Token not found or expired'
            }
          },
          success: false
        }
    else
      {
        data: {
          statusCode: 403,
          body: {
            error: 'access_denied',
            error_description: 'Unsupported authorization method header'
          }
        },
        success: false
      }

  checkBearer: (token) ->
    tokenInstance = @_models.accessToken.fetchByToken token
    if tokenInstance and @_models.accessToken.checkTTL tokenInstance
      tokenInstance
    else
      false

  checkClient: (id, secret) ->
    client = @_models.client.fetchById id
    if client
      @_models.client.checkSecret client, secret
    else
      false

  tokenClientCredentialsController: (clientId) ->
    accessToken = @_models.accessToken.create null, clientId, [], @_models.accessToken.ttl
    {
      "access_token": accessToken,
      "token_type": "bearer",
      "expires_in": @_models.accessToken.ttl,
    }

  tokenPasswordController: (clientId, username, password) ->
    user = @_models.user.fetchByUsername(username)

    if user and @_models.user.checkPassword user, password
      userId = @_models.user.getId user
      refreshToken = @_models.refreshToken.create clientId, userId, []
      accessToken = @_models.accessToken.create clientId, userId, [], @_models.accessToken.ttl
      {
        "refresh_token": refreshToken,
        "access_token": accessToken,
        "token_type": "bearer",
        "expires_in": @_models.accessToken.ttl,
      }
    else
      {
        "error": "invalid_client",
        "error_description": "User not found"
      }

  tokenRefreshTokenController: (refreshToken) ->
    refreshTokenP = @_models.refreshToken.fetchByToken refreshToken
    if refreshTokenP
      userId = @_models.refreshToken.getUserId refreshTokenP
      clientId = @_models.refreshToken.getClientId refreshTokenP
      accessToken = @_models.accessToken.fetchByUserIdClientId userId, clientId
      if accessToken
        token = @_models.accessToken.getToken accessToken
        expires = @_models.accessToken.getTTL accessToken
        {
          "token_type": "bearer",
          "refresh_token": refreshToken,
          "access_token": token,
          "expires_in": expires
        }
      else
        accessToken = @_models.accessToken.create clientId, userId, [], @_models.accessToken.ttl
        {
          "refresh_token": refreshToken,
          "access_token": accessToken,
          "token_type": "bearer",
          "expires_in": @_models.accessToken.ttl,
        }
    else
      {
        "statusCode": 401,
        "body": {
          "error": "invalid_grant",
          "error_description": "Refresh token not found"
        }
      }

  tokenAuthorizationCodeController: (clientId, code) ->
    codeP = @_models.code.fetchByCode(code)
    if codeP and @_models.code.getClientId(codeP) == clientId
      userId = @_models.code.getUserId codeP
      refreshToken = @_models.refreshToken.create clientId, userId, []
      console.warn refreshToken
      accessToken = @_models.accessToken.create clientId, userId, [], @_models.accessToken.ttl
      @_models.code.removeByCode code
      {
        "refresh_token": refreshToken,
        "access_token": accessToken,
        "token_type": "bearer",
        "expires_in": @_models.accessToken.ttl,
      }
    else
      {
        "statusCode": 401,
        "body": {
          "error": "invalid_grant",
          "error_description": "Code not found"
        }
      }

  codeController: (userId, clientId, redirectUri) ->
    client = @_models.client.fetchById clientId
    if client and @_models.client.getRedirectUri(client) == redirectUri
      code = @_models.code.create userId, clientId, [], @_models.code.ttl
      {
        code: code
      }
    else
      {success: false}
  tokenController: (body) ->
    if body.client_id and body.client_secret
      if @checkClient body.client_id, body.client_secret
        switch body.grant_type
          when "password"
            @tokenPasswordController body.client_id, body.username, body.password
          when "refresh_token"
            @tokenRefreshTokenController body.refresh_token
          when "client_credentials"
            @tokenClientCredentialsController body.client_id
          when "authorization_code"
            @tokenAuthorizationCodeController body.client_id, body.code
          else
            {
              "statusCode": 401,
              "body":{
                "error": "unauthorized_client",
                "error_description": "Grant type is not available for the client"
              }
            }
      else
        {
          "statusCode": 401,
          "body": {
            "error": "invalid_client",
            "error_description": "Wrong client id/secret provided"
          }
        }
    else
      {
        "statusCode": 400,
        "body": {
          "error": "invalid_request",
          "error_description": "No authorization header passed"
        }
      }


OAuth2 = @OAuth2;
