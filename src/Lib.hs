module Lib
    ( stunServer
    ) where

import Relude        
import qualified Network.Socket.ByteString as BS
import qualified Network.Socket as S

stunServer :: IO ()
stunServer = S.withSocketsDo $ do
    sock <- S.socket S.AF_INET S.Datagram 0
    S.bindSocket sock (S.SockAddrInet 19900 S.iNADDR_ANY)
    serverLoop sock

serverLoop :: S.Socket -> IO ()
serverLoop sock = do
    (mesg, client) <- BS.recvFrom sock 1500
    send_count <- BS.sendTo sock mesg client
    serverLoop sock
