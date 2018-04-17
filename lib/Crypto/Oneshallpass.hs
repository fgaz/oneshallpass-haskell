{-# LANGUAGE OverloadedStrings #-}
module Crypto.Oneshallpass where

import Crypto.MAC.HMAC
import Crypto.Hash.Algorithms (SHA512)
import Crypto.KDF.PBKDF2
import Crypto.Hash (Digest)
import qualified Data.ByteString as BS
import Data.ByteString.Lazy (toStrict)
import Data.ByteString.Builder (toLazyByteString, intDec, byteStringHex)
import Data.ByteString.Base64 (encode)
import qualified Data.ByteArray as ByteArray
import Data.List (intersperse)
import Data.Foldable (fold)
import Numeric (showHex)

prettyPrint = toLazyByteString . byteStringHex

deriveKey :: BS.ByteString
          -> BS.ByteString
          -> Int
          -> BS.ByteString
deriveKey p e s = fastPBKDF2_SHA512 (Parameters (2^s) 64) p e

myHmac :: BS.ByteString
       -> BS.ByteString
       -> BS.ByteString
       -> Int
       -> Int
       -> HMAC SHA512
myHmac dk e h g i = hmac dk $
  fold
    [ "OneShallPass v2.0"
    , e
    , h
    , toStrict $ toLazyByteString $ intDec g
    , toStrict $ toLazyByteString $ intDec i ]

-- Not compatible with oneshallpass.com yet.
-- But why? What am I doing differently?
-- TODO
f :: BS.ByteString -- ^ Passphrase
  -> BS.ByteString -- ^ Email
  -> Int -- ^ iterations exponent
  -> BS.ByteString -- ^ Host
  -> Int -- ^ Generation
  -> [BS.ByteString]
f p e s h g = results
  where dk = deriveKey p e s
        hmacs = myHmac dk e h g <$> [0..]
        results = encode . BS.pack . ByteArray.unpack . hmacGetDigest <$> hmacs

test = putStrLn
     $ unlines
     $ take 50
     $ filter (\x -> take 14 x == "wfnHT0pXyQSLxn")
     $ take 5000
     $ map show
     $ f "p" "e" 5 "h" 1

