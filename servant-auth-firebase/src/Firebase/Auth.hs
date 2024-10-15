module Firebase.Auth  where

import Servant.API
import Data.Aeson
import Servant.Client
import Data.Generics.Labels ()
import Servant.Client.Generic
import RIO
import Network.HTTP.Client.TLS (getGlobalManager)


-- The Connector provides data required to make calls to the Firebase
-- endpoints.
--data Connector = Connector
--    { cSecureTokenPubKeys :: Conc.MVar (H.HashMap Text JWT.JWK)
--    , cApiKey :: ByteString
--    }
--
--mkConnector :: (MonadIO m) => ByteString -> m Connector
--mkConnector apiKey = do
--    keyStore <- Conc.newMVar H.empty
--    return $ Connector keyStore apiKey

-- A data type for errors when calling the Firebase APIs.
--data ApiErr
--    = -- | A JSON parsing error - if this
--      -- is returned, please report a bug.
--      AEJSONParseErr Text
--    | -- | An error returned by the
--      -- Firebase endpoint. The @Status@
--      -- is the HTTP error code and the
--      -- @Value@ is a raw JSON
--      -- representation of the error
--      -- details.
--      AEApiErr Status Value
--    deriving (Eq, Show)
--
---- The simplest way to call the Firebase APIs provided in this
---- module. Use this if your application does not already have a Monad
---- Transformer stack.
--runIO :: Connector -> ReaderT Connector IO a -> IO a
--runIO = flip runReaderT
--
--setApiKey :: (MonadReader Connector m) => Request -> m Request
--setApiKey r = do
--    key <- asks cApiKey
--    let q = getRequestQueryString r
--    return $ setRequestQueryString (("key", Just key) : q) r
--
--execRequest ::
--    (ToJSON a, MonadReader Connector m, MonadIO m, FromJSON b) =>
--    [Char] ->
--    a ->
--    m (Either ApiErr b)
--execRequest url body = execRequestWithHeader url body []
--
--execRequestWithHeader ::
--    ( ToJSON a
--    , MonadReader Connector m
--    , MonadIO m
--    , FromJSON b
--    ) =>
--    [Char] ->
--    a ->
--    [Header] ->
--    m (Either ApiErr b)
--execRequestWithHeader url body hs = do
--    let r1 = setRequestBodyJSON body $ parseRequest_ url
--        r2 = foldr (\(a, b) -> setRequestHeader a [b]) r1 hs
--    req <- setApiKey r2
--    resp <- httpBS req
--    return $ parseResponse resp
--
--parseResponse :: (FromJSON a) => Response ByteString -> Either ApiErr a
--parseResponse resp = do
--     let st = getResponseStatus resp :: Status
--         body = getResponseBody resp :: ByteString
--     when (st /= status200) $ Left $ AEApiErr st (String $ decodeUtf8 body)
--     case eitherDecodeStrict body of
--        Right v -> Right v
--        Left err -> Left $ AEJSONParseErr $ toS err <> " -  " <> decodeUtf8 body

data LoginResponse = LoginResponse
    { kind :: Text
    , idToken :: Text
    , email :: Text
    , displayName :: Maybe Text
    , refreshTOken :: Maybe Text
    , expiresIn :: Maybe Text
    }
    deriving stock (Show, Eq, Generic)
    deriving anyclass (FromJSON, ToJSON)

data SigninResponse = SigninResponse
    { kind :: Text
    , idToken :: Text
    , email :: Text
    , refreshToken :: Text
    , expiresIn :: Text
    , localId :: Text
    -- , registered :: Bool
    }
    deriving stock (Show, Eq, Generic)
    deriving anyclass (FromJSON, ToJSON)


data EmailPasswordBody = EmailPasswordBody
    { email :: Text
    , password :: Text
    , returnSecureToken :: Bool -- ^ Whether to return a refresh token as well
    }
    deriving stock (Show, Eq, Generic)
    deriving anyclass (FromJSON, ToJSON)


authBaseUrl :: BaseUrl
authBaseUrl = BaseUrl Https "www.googleapis.com" 443 "/identitytoolkit/v3/relyingparty"

data AuthApi mode = AuthApi
    { signupNewUser
        :: mode
            :- "signupNewUser"
                :> ReqBody '[JSON] EmailPasswordBody
                :> QueryParam' '[Required] "key" Text
                :> Post '[JSON] LoginResponse
    , verifyPassword
        :: mode
            :- "verifyPassword"
                :> ReqBody '[JSON] EmailPasswordBody
                :> QueryParam' '[Required] "key" Text
                :> Post '[JSON] LoginResponse
    }
        deriving stock Generic


authClient :: AuthApi (AsClientT ClientM)
authClient = genericClient

apiToken :: Text
apiToken =  "AIzaSyA9LfdjiKwo9WUwDzFylgzIYMwj4q02DlI"

verifyPassword' :: EmailPasswordBody -> IO (Either ClientError LoginResponse)
verifyPassword' body = do
    manager <- getGlobalManager
    let env = mkClientEnv manager authBaseUrl
    runClientM ((authClient ^. #verifyPassword) body apiToken) env

signupNewUser' :: EmailPasswordBody -> IO (Either ClientError LoginResponse)
signupNewUser' body = do
    manager <- getGlobalManager
    let env = mkClientEnv manager authBaseUrl
    runClientM ((authClient ^. #signupNewUser) body apiToken) env

-- Works!
testSignin :: IO (Either ClientError LoginResponse)
testSignin = verifyPassword'  EmailPasswordBody
    {email="tommy@tommyengstrom.com"
    , password = "6tAU%Vxi6^AKMWNn"
    , returnSecureToken = True
    }

-- Works!
testSignup :: IO (Either ClientError LoginResponse)
testSignup = signupNewUser'  EmailPasswordBody
    { email="test1@tommyengstrom.com"
    , password = "hejsanhej123"
    , returnSecureToken = True
    }

-- signinWithIdp ::
--     (MonadReader Connector m, MonadIO m) =>
--     Text ->
--     m (Either ApiErr SigninResponse)
-- signinWithIdp token = do
--     let url = "POST https://identitytoolkit.googleapis.com/v1/accounts:signInWithIdp"
--         body =
--             object
--                 [ "requestUri" .= String "http://localhost/hej"
--                 , "postBody" .= String ("id_token=" <> token <> "&providerId=google.com")
--                 ,"returnSecureToken" .= True
--                 , "returnIdpCredential" .= True
--                 ]
--     print $ encode body
--     execRequest url body
--
-- data RefreshIdResponse = RefreshIdResponse
--     { rirExpiresIn :: Text
--     , rirTokenType :: Text
--     , rirRefreshToken :: Text
--     , rirIdToken :: Text
--     , rirUserId :: Text
--     , rirProjectId :: Text
--     }
--     deriving (Eq, Show)
--
--
-- refreshIdToken ::
--     (MonadReader Connector m, MonadIO m) =>
--     Text ->
--     m (Either ApiErr RefreshIdResponse)
-- refreshIdToken idToken = do
--     let iReq = parseRequest_ "POST https://securetoken.googleapis.com/v1/token"
--         body =
--             [ ("grant_type", "refresh_token")
--             , ("refresh_token", toS $ encodeUtf8 idToken)
--             ]
--     req <- setApiKey $ setRequestBodyURLEncoded body iReq
--     resp <- httpBS req
--     return $ parseResponse resp

-- data ProviderData = ProviderData
--     { providerId :: Text
--     , federatedId :: Text
--     }
--     deriving (Eq, Show, FromJSON, ToJSON)
--
--
-- data UserData = UserData
--     { localId :: Text
--     , email :: Text
--     , emailVerified :: Bool
--     , displayName :: Maybe Text
--     , providerUserInfo :: [ProviderData]
--     , photoUrl :: Maybe Text
--     , passwordHash :: Maybe Text
--     , passwordUpdatedAt :: Scientific -- epochMilliseconds
--     , validSince :: Text -- epochSeconds
--     , disabled :: Maybe Bool
--     , lastLoginAt :: Maybe Text -- epochMilli
--     , createdAt :: Text -- epochMilli
--     , customAuth :: Maybe Bool
--     }
--     deriving (Eq, Show,FromJSON, ToJSON)
--
--
-- data GetUserDataResponse = GetUserDataResponse
--     { kind :: Text
--     , users :: [UserData]
--     }
--     deriving (Eq, Show,FromJSON, ToJSON)
--
--
-- getUserData ::
--     (MonadReader Connector m, MonadIO m) =>
--     Text ->
--     m (Either ApiErr GetUserDataResponse)
-- getUserData idToken = do
--     let url = "POST https://www.googleapis.com/identitytoolkit/v3/relyingparty/getAccountInfo"
--         body = object ["idToken" .= idToken]
--     execRequest url body
--
-- data SendEmailVerificationResp = SendEmailVerificationResp
--     { kind :: Text
--     , email :: Text
--     }
--     deriving (Eq, Show, FromJSON, ToJSON)
--
--
-- sendEmailVerification ::
--     (MonadReader Connector m, MonadIO m) =>
--     Text ->
--     m (Either ApiErr SendEmailVerificationResp)
-- sendEmailVerification idToken = do
--     let url = "POST https://www.googleapis.com/identitytoolkit/v3/relyingparty/getOobConfirmationCode"
--         body =
--             object
--                 [ "requestType" .= ("VERIFY_EMAIL" :: Text)
--                 , "idToken" .= idToken
--                 ]
--     execRequest url body
--
-- data ConfirmEmailVerificationResp = ConfirmEmailVerificationResp
--     { kind :: Text
--     , localId :: Maybe Text
--     , email :: Text
--     , displayName :: Maybe Text
--     , photoUrl :: Maybe Text
--     , passwordHash :: Maybe Text
--     , providerUserInfo :: [ProviderData]
--     , emailVerified :: Bool
--     }
--     deriving (Eq, Show, FromJSON, ToJSON)
--
--
-- confirmEmailVerification ::
--     (MonadReader Connector m, MonadIO m) =>
--     Text ->
--     m (Either ApiErr ConfirmEmailVerificationResp)
-- confirmEmailVerification oobCode = do
--     let url = "POST https://www.googleapis.com/identitytoolkit/v3/relyingparty/setAccountInfo"
--         body = object ["oobCode" .= oobCode]
--     execRequest url body
--
-- data PasswordResetEmailResp = PasswordResetEmailResp
--     { prerKind :: Text
--     , prerEmail :: Text
--     }
--     deriving (Eq, Show)
--
--
-- sendPasswordResetEmail ::
--     (MonadReader Connector m, MonadIO m) =>
--     Text ->
--     Maybe Text ->
--     m (Either ApiErr PasswordResetEmailResp)
-- sendPasswordResetEmail email localeM = do
--     let url = "POST https://www.googleapis.com/identitytoolkit/v3/relyingparty/getOobConfirmationCode"
--         body =
--             object
--                 [ "requestType" .= ("PASSWORD_RESET" :: Text)
--                 , "email" .= email
--                 ]
--     maybe
--         (execRequest url body)
--         ( execRequestWithHeader url body
--             . (\v -> [("X-Firebase-Locale", toS $ encodeUtf8 v)])
--         )
--         localeM
--
-- data PasswordResetResp = PasswordResetResp
--     { prrKind :: Text
--     , prrEmail :: Text
--     , prrRequestType :: Text
--     }
--     deriving (Eq, Show)
--
--
-- verifyPasswordResetCode ::
--     (MonadReader Connector m, MonadIO m) =>
--     Text ->
--     m (Either ApiErr PasswordResetResp)
-- verifyPasswordResetCode oobCode = do
--     let url = "POST https://www.googleapis.com/identitytoolkit/v3/relyingparty/resetPassword"
--         body = object ["oobCode" .= oobCode]
--     execRequest url body
--
-- confirmPasswordReset ::
--     (MonadReader Connector m, MonadIO m) =>
--     Text ->
--     Text ->
--     m (Either ApiErr PasswordResetResp)
-- confirmPasswordReset oobCode newPassword = do
--     let url = "POST https://www.googleapis.com/identitytoolkit/v3/relyingparty/resetPassword"
--         body =
--             object
--                 [ "oobCode" .= oobCode
--                 , "newPassword" .= newPassword
--                 ]
--     execRequest url body
--
-- {- $use
--
--  If your application already contains an Monad Transformer stack
--  (and it is an instance of MonadIO and MonadReader -- this is quite
--  common), then just add the Firebase.Auth.Connector to your reader
--  environment, and use Control.Monad.Reader.withReader to modify the
--  environment when calling functions in this module.
--
--  The simplest usage is in the `ReaderT Connector IO a` monad, as
--  used by the @runIO@ function. Just provide the Firebase API Key:
--
--  > result <- runIO "myAPIKeyxxx..." $
--  >           signupWithEmailAndPassword "user@example.com" "secret"
--  > case result of
--  >     Right signupResp -> print signupResp
--  >     Left apiErr -> print $ "Error: " ++ show apiErr
-- -}
--
-- data AuthError
--     = AEPublicKeyFetchHTTPStatus HT.Status
--     | AECertParseError Text
--     | AEUnexpectedCertFormat
--     | AEInvalidToken
--     | AEInvalidTokenHeader Text
--     | AEUnknownKid
--     | AETokenDecode Text
--     | AEVerification Text
--     | AEPayloadDecode Text
--     | AEUnknown Text
--     deriving (Eq, Show)
--
-- instance Exception AuthError
--
-- loadSecureTokenSigningKeys ::
--     (MonadIO m) =>
--     m (Either AuthError (H.HashMap Text JWT.JWK))
-- loadSecureTokenSigningKeys = do
--     let url = "GET https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com"
--         req = parseRequest_ url
--     resp <- httpJSONEither req
--     let st = getResponseStatus resp
--         body = getResponseBody resp
--     pure $ do
--         when (st /= status200) $ Left $ AEPublicKeyFetchHTTPStatus st
--
--         parseKeys $
--                     fmapL (AECertParseError . show) $
--                         getResponseBody resp
--   where
--     fromCertRaw :: ByteString -> Either AuthError X509.Certificate
--     fromCertRaw s = do
--         pems <- fmapL (AECertParseError . toS) $ Pem.pemParseBS s
--         pem <- note (AECertParseError "No pem found") $ headMay pems
--         signedExactCert <-
--             fmapL (AECertParseError . toS) $
--                 X509.decodeSignedCertificate $
--                     Pem.pemContent pem
--         let sCert = X509.getSigned signedExactCert
--             cert = X509.signedObject sCert
--         return cert
--
--     getRSAKey (X509.PubKeyRSA (PublicKey size n e)) = Just (size, n, e)
--     getRSAKey _ = Nothing
--
--     certToJwk :: X509.Certificate -> Either AuthError JWT.JWK
--     certToJwk cert = do
--         (size, _n, e) <-
--             note AEUnexpectedCertFormat $
--                 getRSAKey $
--                     X509.certPubKey cert
--         let jwk =
--                 JWK.fromKeyMaterial $
--                     JWK.RSAKeyMaterial $
--                         JWK.RSAKeyParameters
--                             (JTypes.Base64Integer (fromIntegral size))
--                             (JTypes.Base64Integer e)
--                             Nothing
--             jwk' = jwk & JWK.jwkKeyOps ?~ [JWK.Verify]
--         return jwk'
--
--     parseKeys ::
--         Either AuthError (H.HashMap Text Text) ->
--         Either AuthError (H.HashMap Text JWT.JWK)
--     parseKeys b = do
--         rawCertsMap <- H.map (toS . encodeUtf8) <$> b
--         certsPairList <- forM (H.toList rawCertsMap) $ \(k, v) -> do
--             cert <- fromCertRaw v
--             return (k, cert)
--         keyPairList <- forM certsPairList $ \(k, v) -> do
--             jwk <- certToJwk v
--             return (k, jwk)
--         return $ H.fromList keyPairList
--
-- -- Takes a token, parses header info and returns a pair of (algo, kid)
-- getTokenInfo :: ByteString -> Either AuthError (Text, Text)
-- getTokenInfo token = do
--     header <- note AEInvalidToken $ headMay $ B8.split '.' token
--     v <-
--         fmapL (AEInvalidTokenHeader . show) $
--             eitherDecodeStrict $
--                 B64.decodeLenient header
--     let [alg, kid] = ["alg", "kid"] :: [Text]
--     note
--         (AEInvalidTokenHeader "Missing alg or kid")
--         ((,) <$> H.lookup alg v <*> H.lookup kid v)
--
-- verifyToken ::
--     ByteString ->
--     H.HashMap Text JWT.JWK ->
--     IO (Either AuthError Value)
-- verifyToken token keyStore = do
--     let resE = do
--             (_, kid) <- getTokenInfo token
--             jwk <- note AEUnknownKid $ H.lookup kid keyStore
--             jws <-
--                 fmapL (AETokenDecode . show) $
--                     (decodeCompact (toS token) :: Either JWT.Error JWT.SignedJWT)
--             return (jwk, jws)
--     pPrint resE
--     case resE of
--         Left err -> return $ Left err
--         Right (jwk, jws) -> runExceptT $ do
--             claims <-
--                  fmapLT (AEVerification . (show :: JWT.JWTError -> Text)) $
--                      JWT.verifyClaims (JWT.defaultJWTValidationSettings (const True)) jwk jws
--             return $ toJSON claims
--
-- verifyTokenWithKeyReload ::
--     (MonadIO m) =>
--     ByteString ->
--     H.HashMap Text JWT.JWK ->
--     Bool ->
--     m (Either AuthError (H.HashMap Text JWT.JWK, Value))
-- verifyTokenWithKeyReload token keyStore isReloaded =
--     case getTokenInfo token of
--         Left err -> return $ Left err
--         Right (_, kid)
--             | H.member kid keyStore -> runExceptT $ do
--                 payload <- ExceptT $ liftIO $ verifyToken token keyStore
--                 return (keyStore, payload)
--             | isReloaded -> return $ Left AEUnknownKid
--             | otherwise -> do
--                 newStoreE <- loadSecureTokenSigningKeys
--                 either
--                     (return . Left)
--                     (\store -> verifyTokenWithKeyReload token store True)
--                     newStoreE
--
-- {- | Verify an id token. This extracts the signature, and verifies it by
--  automatically fetching Google Token API's public key, and checking
--  details in the request.
-- -}
-- extractTokenClaims ::
--     (MonadReader Connector m, MonadIO m, MonadUnliftIO m) =>
--     ByteString ->
--     m (Either AuthError Value)
-- extractTokenClaims token = do
--     keyStoreVar <- asks cSecureTokenPubKeys
--     Conc.modifyMVar keyStoreVar $ \keyStore -> do
--         res <- verifyTokenWithKeyReload token keyStore False
--         case res of
--             Left err -> return (keyStore, Left err)
--             Right (newStore, val) -> return (newStore, Right val)
