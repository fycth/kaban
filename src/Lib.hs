module Lib
  ( stunServer
  ) where

import           Data.Binary.Get            as G
import           Data.Binary.Put            as P
import qualified Data.ByteString            as BS
import           Data.ByteString.Char8      (readInt)
import qualified Data.ByteString.Conversion as BSC
import qualified Data.ByteString.Lazy       as BL
import           Data.Hex                   (hex)
import qualified Network.Socket             as S
import qualified Network.Socket.ByteString  as NBS
import           Relude
import           Text.Printf

data Header = Header
  { messageType :: !Word16
  , messageLength :: !Word16
  , magicCookie :: !Word32
  , transactionID :: !BS.ByteString }

stunServer :: IO ()
stunServer = S.withSocketsDo $ do
  addr <- resolve "19900"
  sock <- S.socket (S.addrFamily addr) (S.addrSocketType addr) (S.addrProtocol addr)
  S.bind sock (S.addrAddress addr)
  serverLoop sock

serverLoop :: S.Socket -> IO ()
serverLoop sock = do
  (mesg, client) <- NBS.recvFrom sock 1500
  sent <- case G.runGetIncremental parseHeader `G.pushChunk` mesg of
    Done _ _ h ->
      do
        putStrLn $ printf "0x%08X" (magicCookie h)
        let r = BS.concat . BL.toChunks $ P.runPut $ encodeHeader $ Header 0x101 0x0 0x2112A442 "0"
        NBS.sendTo sock r client
    _ ->
      do
        putStrLn "nope"
        let r = BS.concat . BL.toChunks $ P.runPut $ encodeHeader $ Header 0x111 0x0 0x2112A442 "0"
        NBS.sendTo sock r client
  serverLoop sock

resolve :: String -> IO S.AddrInfo
resolve port = do
  let hints = S.defaultHints { S.addrFlags = [S.AI_PASSIVE, S.AI_ALL], S.addrSocketType = S.Datagram }
  addr:_ <- S.getAddrInfo (Just hints) Nothing (Just port)
  return addr

parseHeader :: G.Get Header
parseHeader = do
  messageType <- G.getWord16be
  messageLength <- G.getWord16be
  magicCookie <- G.getWord32be
  transactionID <- G.getByteString 12
  return $ Header messageType messageLength magicCookie transactionID

encodeHeader :: Header -> P.Put
encodeHeader h = do
  P.putWord16be $ messageType h
  P.putWord16be $ messageLength h
  P.putWord32be $ magicCookie h
  P.putByteString $ transactionID h
