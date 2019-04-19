module Lib
  ( stunServer
  ) where

import           Data.Binary.Get            as G
import           Data.Binary.Put            as P
import qualified Data.ByteString            as BS
import qualified Data.ByteString.Conversion as BSC
import qualified Data.ByteString.Lazy       as BL
--import           Data.Hex                   (hex)
import qualified Data.ByteString.Builder    as BSB
import qualified Network.Socket             as S
import qualified Network.Socket.ByteString  as NBS
import           Relude
import           Text.Printf                (printf)

data Header = Header
  { messageType :: !Word16
  , messageLength :: !Word16
  , magicCookie :: !Word32
  , transactionID :: !BS.ByteString }

data IpAddr = Ip4 Word32 | Ip6 Word32 Word32 Word32 Word32

data Attribute = Attribute
  { attributeType :: !Word16
  , attributeLen :: !Word16
  , attributeVal :: !BS.ByteString }

data StunResponse = StunResponse
  { header :: Header
  , attributes :: []Attribute }

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
        let r = BS.concat . BL.toChunks $ P.runPut $ encodeResponse $ generateResponse client $ transactionID h
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

-- generateMockResponse :: BS.ByteString -> StunResponse
-- generateMockResponse transactionId =
--   let
--     header = Header 0x101 12 0x2112A442 transactionId
--     attribute = Attribute 0x0020 8 (BS.pack [0x0, 0x01, 0xc9, 0xa3, 0x7c, 0x5c, 0xc6, 0xd0])
--     attributes = [attribute]
--   in
--     StunResponse header attributes

encodeResponse :: StunResponse -> P.Put
encodeResponse response = do
  encodeHeader $ header response
  encodeAttribute $ attributes response

encodeAttribute :: []Attribute -> P.Put
encodeAttribute [] = return ()
encodeAttribute (a:as) = do
  P.putWord16be $ attributeType a
  P.putWord16be $ attributeLen a
  P.putByteString $ attributeVal a
  encodeAttribute as

generateResponse :: S.SockAddr -> BS.ByteString -> StunResponse
generateResponse client tid =  
  let    
    attr = case client of
      S.SockAddrInet port host ->
        makeMappedAddressAttribute (fromIntegral port :: Word16) (Ip4 host)
      S.SockAddrInet6 port _ (h1,h2,h3,h4) _ ->
        makeMappedAddressAttribute (fromIntegral port :: Word16) (Ip6 h1 h2 h3 h4)
      _ ->
        Attribute 0x0020 8 (BS.pack [0x0, 0x01, 0xc9, 0xa3, 0x7c, 0x5c, 0xc6, 0xd0])
    l = 4 + attributeLen attr
    header = Header 0x101 l 0x2112A442 tid    
  in
    StunResponse header [attr]      

makeMappedAddressAttribute :: Word16 -> IpAddr -> Attribute
makeMappedAddressAttribute port host =
  let
    p = BS.pack $ encodeWord16 $ fromIntegral port
    a = case host of
      Ip4 h ->
        BS.pack $ encodeWord32 h  
      Ip6 h1 h2 h3 h4 ->
        BS.pack $ encodeWord32 h1 ++ encodeWord32 h2 ++ encodeWord32 h3 ++ encodeWord32 h4
    ipv = case host of 
      Ip4 _ -> 0x01
      _ -> 0x02
    v = BS.pack [0x0, ipv] `BS.append` p `BS.append` a
    l = fromIntegral(BS.length v) :: Word16
  in
    Attribute 0x0001 l v

encodeWord16 :: Word16 -> [Word8]
encodeWord16 = BL.unpack . BSB.toLazyByteString . BSB.word16BE

encodeWord32 :: Word32 -> [Word8]
encodeWord32 = BL.unpack . BSB.toLazyByteString . BSB.word32BE
