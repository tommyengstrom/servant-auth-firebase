{-# LANGUAGE DataKinds #-}
{-# LANGUAGE LambdaCase #-}

module ApiSpec where

import Control.Monad.Reader
import Control.Monad.Time
import Data.ByteString (ByteString)
import Data.ByteString.Lazy qualified as BL
import Data.Text.Encoding (encodeUtf8)
import Data.Time
import Network.Wai.Handler.Warp qualified as Warp
import Servant
import Servant.Auth.Firebase
import Test.Hspec
import Prelude

type Api = Get '[JSON] String

type ProtectedApi = FirebaseAuth FirebaseUser :> Api

server :: Server ProtectedApi
server = \case
    Authenticated user -> pure $ show user
    AuthenticationFailure t -> throwError (err401{errBody = BL.fromStrict $ encodeUtf8 t})

app :: FirebaseSettings -> Application
app authSettings =
    serveWithContext
        (Proxy @ProtectedApi)
        (authSettings :. EmptyContext)
        server

-- | Start a server that can be queried with
--  `curl localhost:7878 -H "Authorization: Bearer .."`
runApp :: IO ()
runApp = do
    authSettings <- mkFirebaseVerificationSettings "sweq-378105"
    Warp.run 7878 $ app authSettings

-- | A sample token that is valid at sampleTokenTime.
-- If tests fail the keys have probably changed and you need to change the token.
sampleToken :: ByteString
sampleToken =
    "eyJhbGciOiJSUzI1NiIsImtpZCI6IjhkOWJlZmQzZWZmY2JiYzgyYzgzYWQwYzk3MmM4ZWE5NzhmNmYxMzciLCJ0eXAiOiJKV1QifQ.eyJuYW1lIjoiVG9tbXkgRW5nc3Ryb20iLCJpc3MiOiJodHRwczovL3NlY3VyZXRva2VuLmdvb2dsZS5jb20vc3dlcS0zNzgxMDUiLCJhdWQiOiJzd2VxLTM3ODEwNSIsImF1dGhfdGltZSI6MTcyNjQ4NDU0NywidXNlcl9pZCI6InZYS3daeFFQWmxRQm1rM2VBdTYxWFowaEppczEiLCJzdWIiOiJ2WEt3WnhRUFpsUUJtazNlQXU2MVhaMGhKaXMxIiwiaWF0IjoxNzI4NjQ3ODU4LCJleHAiOjE3Mjg2NTE0NTgsImVtYWlsIjoidG9tbXlAdG9tbXllbmdzdHJvbS5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiZmlyZWJhc2UiOnsiaWRlbnRpdGllcyI6eyJlbWFpbCI6WyJ0b21teUB0b21teWVuZ3N0cm9tLmNvbSJdfSwic2lnbl9pbl9wcm92aWRlciI6InBhc3N3b3JkIn19.d6qeyNc-HBE-RWoJzHjt4LuotxseA6J1WP4tAyJqM889noll-u7CG9wnQ47oidK-RplaTtxcLXBNXELZcrd5dBBJQ2dExkEsAuC0sPHwePeumxowJ0a9nnHza3ESMI81Je0WcfivFPxEVUJzgg04D0DAAA4h_o5d9Jz5pweO6hNJiGeiqU_wnONjvH-c4LkLpE7if9yVf-xEl9iLtnl95YBx-yxQLW3Z2DE8he1rkeCwpJFe1sNHffXA1aLTgtwi8SqnbyHJchgfjUh0KRZ6dlPghw1YZ0-dW9eG5nYYL-NRMhgJ6cXa30AAFMpReI3PCF_YeGXCOR2xe43xLe-P_A"

sampleTokenTime :: UTCTime
sampleTokenTime = UTCTime (fromGregorian 2024 10 11) (12 * 3600)

sampleTokenExpiredTime :: UTCTime
sampleTokenExpiredTime = addUTCTime 3600 sampleTokenTime

newtype TestMonad a = TestMonad (ReaderT UTCTime IO a)
    deriving newtype (Functor, Applicative, Monad, MonadIO)

instance MonadTime TestMonad where
    currentTime = TestMonad ask
    monotonicTime = do
        t <- TestMonad ask
        let base = UTCTime (fromGregorian 1970 1 1) 0
        pure $ fromRational $ toRational $ diffUTCTime t base


runTestAt :: UTCTime -> TestMonad a -> IO a
runTestAt t (TestMonad m) = runReaderT m t

spec :: Spec
spec = describe "veirfyFirebaseJWT" $ do
    it "Accepts my old token at the right time" $ do
        -- If this fails they have probably changed the keys and you need to change the
        -- sample token to make the tests pass again.
        authSettings <- mkFirebaseVerificationSettings "sweq-378105"
        r <- runTestAt sampleTokenTime $ checkFirebaseToken @FirebaseUser authSettings sampleToken
        r `shouldSatisfy` \case
            Authenticated _ -> True
            AuthenticationFailure _ -> False
    it "My old token has now expired" $ do
        authSettings <- mkFirebaseVerificationSettings "sweq-378105"
        r <-
            runTestAt sampleTokenExpiredTime $
                checkFirebaseToken @FirebaseUser authSettings sampleToken
        r `shouldBe` AuthenticationFailure "Token has expired"
