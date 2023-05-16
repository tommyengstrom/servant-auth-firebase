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
    "eyJhbGciOiJSUzI1NiIsImtpZCI6ImU3OTMwMjdkYWI0YzcwNmQ2ODg0NGI4MDk2ZTBlYzQzMjYyMjIwMDAiLCJ0eXAiOiJKV1QifQ.eyJuYW1lIjoiVG9tbXkgRW5nc3Ryb20iLCJpc3MiOiJodHRwczovL3NlY3VyZXRva2VuLmdvb2dsZS5jb20vc3dlcS0zNzgxMDUiLCJhdWQiOiJzd2VxLTM3ODEwNSIsImF1dGhfdGltZSI6MTY4MjQ5MzIwMSwidXNlcl9pZCI6InZYS3daeFFQWmxRQm1rM2VBdTYxWFowaEppczEiLCJzdWIiOiJ2WEt3WnhRUFpsUUJtazNlQXU2MVhaMGhKaXMxIiwiaWF0IjoxNjgyNDkzMjAxLCJleHAiOjE2ODI0OTY4MDEsImVtYWlsIjoidG9tbXlAdG9tbXllbmdzdHJvbS5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiZmlyZWJhc2UiOnsiaWRlbnRpdGllcyI6eyJlbWFpbCI6WyJ0b21teUB0b21teWVuZ3N0cm9tLmNvbSJdfSwic2lnbl9pbl9wcm92aWRlciI6InBhc3N3b3JkIn19.Owe0FvflTEIQoMeuQQZMO3PtEJK0_W4dRNeM8CAY3QLf3rwfxn-icPdXoIsLKzhWdZghpwaXWsPyDg_6DOt4lAf8oXJ37UdFBwXZ84yCxLb9J2BJySNjBePUKMh81Pojtv34KBwn0PgLqAhAzrBU2SV2rHPS6xQfiUtZZt1NG8fpQr5co8RAAxakVa2gLcuBiQDCG9SkMoE2s-L7MjaiiN-7VEM262fBvHLyt4FS8J3yzGbBi83vUKYrIjKWTRUs8rZ0_fAcgJHVZhqmJw9_wg1xugmAnwQeoZskbYXhKGjg8H5jmfYcoyi_TCHSs8PiYwL6blQhonYSu-vBFHbOQA"

sampleTokenTime :: UTCTime
sampleTokenTime = UTCTime (fromGregorian 2023 4 26) (8 * 3600)

sampleTokenExpiredTime :: UTCTime
sampleTokenExpiredTime = addUTCTime 3600 sampleTokenTime

newtype TestMonad a = TestMonad (ReaderT UTCTime IO a)
    deriving newtype (Functor, Applicative, Monad, MonadIO)

instance MonadTime TestMonad where
    currentTime = TestMonad ask

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
