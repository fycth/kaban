-- https://tools.ietf.org/html/rfc5389
-- this is an RFC5389 implementation of STUN server

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

data AddressAttributeType = XMapped | Mapped 

stunServer :: IO ()
stunServer = S.withSocketsDo $ do
  addr <- resolve "19900"
  sock <- S.socket (S.addrFamily addr) (S.addrSocketType addr) (S.addrProtocol addr)
  S.bind sock (S.addrAddress addr)
  serverLoop sock

serverLoop :: S.Socket -> IO ()
serverLoop sock = do
  (mesg, client) <- NBS.recvFrom sock 1500
  r <- case G.runGetIncremental parseHeader `G.pushChunk` mesg of
        Done _ _ h ->
          do
            putStrLn $ printf "0x%08X" (magicCookie h)
            return $ BS.concat . BL.toChunks $ P.runPut $ encodeResponse $ generateResponse client $ transactionID h
        _ ->
          do
            let 
              attrVal = "Bad request"
              attrLen = fromIntegral(BS.length attrVal) :: Word16
              attr = Attribute 0x400 attrLen attrVal 
              l = 4 + attributeLen attr
            return $ BS.concat . BL.toChunks $ P.runPut $ encodeHeader $ Header 0x111 l mCookie "0"
  sent <- NBS.sendTo sock r client      
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
    xorString = encodeWord32 mCookie ++ (BL.unpack $ BL.fromStrict tid)
    attr = case client of
      S.SockAddrInet port host ->
        createMappedAddressAttribute (fromIntegral port :: Word16) (Ip4 host) xorString Mapped
      S.SockAddrInet6 port _ (h1,h2,h3,h4) _ ->
        createMappedAddressAttribute (fromIntegral port :: Word16) (Ip6 h1 h2 h3 h4) xorString XMapped 
      _ ->
-- fake response: todo error message
        Attribute 0x0020 8 (BS.pack [0x0, 0x01, 0xc9, 0xa3, 0x7c, 0x5c, 0xc6, 0xd0])
    l = 4 + attributeLen attr
    header = Header 0x101 l mCookie tid
  in
    StunResponse header [attr]
    
createMappedAddressAttribute :: Word16 -> IpAddr -> [Word8] -> AddressAttributeType -> Attribute
createMappedAddressAttribute port host xorString at =
  let
    atype = case at of
      XMapped -> 0x20
      Mapped -> 0x01
    p = encodeWord16 (fromIntegral port)
    pe = case at of
      XMapped -> xorWord8 p xorString []
      Mapped -> p
    a = case host of
      Ip4 h ->
        encodeWord32 h
      Ip6 h1 h2 h3 h4 ->
        encodeWord32 h1 ++ encodeWord32 h2 ++ encodeWord32 h3 ++ encodeWord32 h4
    ae = case at of
      XMapped -> xorWord8 a xorString []
      Mapped -> a
    v = BS.pack (getAddressFamily host) `BS.append` BS.pack pe `BS.append` BS.pack ae
    l = fromIntegral(BS.length v) :: Word16
  in
    Attribute atype l v

encodeWord16 :: Word16 -> [Word8]
encodeWord16 = BL.unpack . BSB.toLazyByteString . BSB.word16BE

encodeWord32 :: Word32 -> [Word8]
encodeWord32 = BL.unpack . BSB.toLazyByteString . BSB.word32BE

mCookie :: Word32
mCookie = 0x2112A442

xorWord8 :: [Word8] -> [Word8] -> [Word8] -> [Word8]
xorWord8 [] _ a = a
xorWord8 (x:xs) (y:ys) a = xorWord8 xs ys (a ++ [xor x y])

getAddressFamily :: IpAddr -> [Word8]
getAddressFamily host =
  let
    f = case host of
      Ip4 _ -> 0x01
      _ -> 0x02
  in
    [0x00, f]  
