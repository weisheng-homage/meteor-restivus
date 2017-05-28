@OAuth2 or= {}

@OAuth2.grant = (clientId, redirectUri) ->
  Meteor.call(
    'oauth2Grant',
    clientId,
    redirectUri,
    (err, result) ->
      if err
        throw err
      else
        window.location=result
  )
OAuth2 = @OAuth2;
