module Lib
    ( stunServer
    ) where

import qualified Network.Socket as S
import Network.Socket (Socket)

stunServer :: IO ()
stunServer = S.withSocketsDo $ do
    sock <- S.socket S.AF_INET S.Datagram 0
    S.bindSocket sock (S.SockAddrInet 19900 S.iNADDR_ANY)
    serverLoop sock

serverLoop :: Socket -> IO ()
serverLoop sock = do
    (mesg, recv_count, client) <- S.recvFrom sock 1500
    send_count <- S.sendTo sock mesg client
    serverLoop sock
