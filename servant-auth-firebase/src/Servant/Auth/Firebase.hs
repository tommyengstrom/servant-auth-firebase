module Servant.Auth.Firebase where

import Control.Monad.Except
import Control.Monad.Time (MonadTime (..))
import Crypto.JWT qualified as JWT
import Data.Aeson
import Data.Aeson.Key qualified as Key
import Data.Aeson.KeyMap qualified as KM
import Data.ByteString qualified as BS
import Data.ByteString.Lazy qualified as BL
import Data.Char (isUpper, toLower)
import Data.Kind
import Data.List (foldl')
import Data.Map qualified as M
import Data.Maybe
import Data.Text (Text)
import Data.Text qualified as T
import Firebase.JWK.Store qualified as FB
import GHC.Generics (Generic)
import Lens.Micro
import Network.HTTP.Types
import Network.Wai qualified as Wai
import Servant
import Servant.Server.Internal.Delayed (Delayed (..), addAuthCheck)
import Servant.Server.Internal.DelayedIO (DelayedIO, withRequest)
import Servant.Server.Internal.Router (Router)
import Prelude

data FirebaseSettings = FirebaseSettings
    { jwkSet :: JWT.JWKSet
    , validationSettings :: JWT.JWTValidationSettings
    }
    deriving (Generic)

type FirebaseProjectId = JWT.StringOrURI

mkFirebaseVerificationSettings :: MonadIO m => FirebaseProjectId -> m FirebaseSettings
mkFirebaseVerificationSettings projectId = do
    jwkSet <- JWT.JWKSet <$> liftIO FB.getCurrentKeys
    pure
        FirebaseSettings
            { jwkSet = jwkSet
            , validationSettings = JWT.defaultJWTValidationSettings (== projectId)
            }

data FirebaseAuth (user :: Type)
data FirebaseJWT

data VerifiedClaims a = VerifiedClaims
    { iss :: Maybe JWT.StringOrURI
    , sub :: Maybe JWT.StringOrURI
    , aud :: Maybe JWT.Audience
    , exp :: Maybe JWT.NumericDate
    , nbf :: Maybe JWT.NumericDate
    , iat :: Maybe JWT.NumericDate
    , jti :: Maybe T.Text
    , content :: a
    }
    deriving (Show, Eq, Generic)

data FirebaseUser = FirebaseUser
    { name :: Text
    , userId :: Text
    , email :: Text
    , emailVerified :: Bool
    }
    deriving (Show, Eq, Generic)

jsonOptions :: Options
jsonOptions =
    defaultOptions
        { fieldLabelModifier = toSnakeCase
        }

toSnakeCase :: String -> String
toSnakeCase = foldl' (\b a -> b <> if isUpper a then '_' : [toLower a] else [a]) ""

instance ToJSON FirebaseUser where
    toJSON = genericToJSON jsonOptions
instance FromJSON FirebaseUser where
    parseJSON = genericParseJSON jsonOptions

data FirebaseAuthResult user
    = Authenticated user
    | AuthenticationFailure Text
    deriving (Show, Eq, Generic)

instance
    ( HasServer api ctx
    , FromJSON user
    , HasContextEntry ctx FirebaseSettings
    ) =>
    HasServer (FirebaseAuth user :> api) ctx
    where
    type ServerT (FirebaseAuth user :> api) m = FirebaseAuthResult user -> ServerT api m

    hoistServerWithContext ::
        forall (m :: Type -> Type) (n :: Type -> Type).
        Proxy (FirebaseAuth user :> api) ->
        Proxy ctx ->
        (forall x. m x -> n x) ->
        (FirebaseAuthResult user -> ServerT api m) ->
        FirebaseAuthResult user ->
        ServerT api n
    hoistServerWithContext _ pc nt s = hoistServerWithContext (Proxy @api) pc nt . s

    route ::
        forall env.
        Proxy (FirebaseAuth user :> api) ->
        Context ctx ->
        Delayed env (FirebaseAuthResult user -> Server api) ->
        Router env
    route _ ctx subserver =
        route
            (Proxy @api)
            ctx
            (subserver `addAuthCheck` authCheck)
      where
        authCheck :: DelayedIO (FirebaseAuthResult user)
        authCheck = withRequest $ \req -> liftIO $ do
            case getAuthorizationToken $ Wai.requestHeaders req of
                Nothing ->
                    pure $
                        AuthenticationFailure "No bearer token found in `Authorization` header"
                Just token -> do
                    user <- checkFirebaseToken (getContextEntry ctx) token
                    pure user

checkFirebaseToken ::
    forall user m.
    ( FromJSON user
    , MonadTime m
    ) =>
    FirebaseSettings ->
    BS.ByteString ->
    m (FirebaseAuthResult user)
checkFirebaseToken settings tok = do
    verificationResult <- runExceptT $ do
        jwt <- JWT.decodeCompact $ BL.fromStrict tok
        JWT.verifyClaims (validationSettings settings) (jwkSet settings) jwt
    case verificationResult of
        Right claims -> do
            let object :: Value
                object =
                    claims
                        ^. JWT.unregisteredClaims
                            . to (M.mapKeys (Key.fromText))
                            . to (KM.fromMap)
                            . to Object
            pure $ case fromJSON object of
                Success u -> Authenticated u
                Error err ->
                    AuthenticationFailure $
                        "Error decoding verified claims: "
                            <> T.pack err
        Left err' -> pure $ case err' of
            JWT.JWSError err -> AuthenticationFailure . T.pack $ show err
            JWT.JWTClaimsSetDecodeError err ->
                AuthenticationFailure $ "JWTClaimsSetDecodeError: " <> T.pack err
            JWT.JWTExpired -> AuthenticationFailure "Token has expired"
            JWT.JWTNotYetValid -> AuthenticationFailure "NotYetValid"
            JWT.JWTNotInIssuer -> AuthenticationFailure "NotInIssuer"
            JWT.JWTNotInAudience -> AuthenticationFailure "NotInAudience"
            JWT.JWTIssuedAtFuture -> AuthenticationFailure "IssuedAtFuture"

getAuthorizationToken :: RequestHeaders -> Maybe BS.ByteString
getAuthorizationToken headers = do
    rawAuthHeaderValue <- listToMaybe $ do
        (headerName, v) <- headers
        guard $ headerName == "authorization"
        pure v
    BS.stripPrefix "Bearer " rawAuthHeaderValue
