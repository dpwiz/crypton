-- |
-- Module      : Crypto.PubKey.Ed25519
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- Ed25519 support
--
{-# LANGUAGE BangPatterns               #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module Crypto.PubKey.Ed25519
    ( SecretKey
    , PublicKey
    , Signature
    -- * Size constants
    , publicKeySize
    , secretKeySize
    , signatureSize
    -- * Smart constructors
    , signature
    , publicKey
    , secretKey
    -- * Methods
    , toPublic
    , sign
    , signLazy
    , verify
    , generateSecretKey
    ) where

import qualified Data.ByteString.Lazy as L
import           Data.Word
import           Foreign.C.Types
import           Foreign.Marshal.Array
import           Foreign.Ptr
import           Foreign.Storable

import           Crypto.Error
import           Crypto.Internal.ByteArray (ByteArrayAccess, Bytes,
                                            ScrubbedBytes, withByteArray)
import qualified Crypto.Internal.ByteArray as B
import           Crypto.Internal.Compat
import           Crypto.Internal.Imports
import           Crypto.Random

-- | An Ed25519 Secret key
newtype SecretKey = SecretKey ScrubbedBytes
    deriving (Show,Eq,ByteArrayAccess,NFData)

-- | An Ed25519 public key
newtype PublicKey = PublicKey Bytes
    deriving (Show,Eq,ByteArrayAccess,NFData)

-- | An Ed25519 signature
newtype Signature = Signature Bytes
    deriving (Show,Eq,ByteArrayAccess,NFData)

-- | Try to build a public key from a bytearray
publicKey :: ByteArrayAccess ba => ba -> CryptoFailable PublicKey
publicKey bs
    | B.length bs == publicKeySize =
        CryptoPassed $ PublicKey $ B.copyAndFreeze bs (\_ -> return ())
    | otherwise =
        CryptoFailed $ CryptoError_PublicKeySizeInvalid

-- | Try to build a secret key from a bytearray
secretKey :: ByteArrayAccess ba => ba -> CryptoFailable SecretKey
secretKey bs
    | B.length bs == secretKeySize = unsafeDoIO $ withByteArray bs initialize
    | otherwise                    = CryptoFailed CryptoError_SecretKeyStructureInvalid
  where
        initialize inp = do
            valid <- isValidPtr inp
            if valid
                then (CryptoPassed . SecretKey) <$> B.copy bs (\_ -> return ())
                else return $ CryptoFailed CryptoError_SecretKeyStructureInvalid
        isValidPtr _ =
            return True
{-# NOINLINE secretKey #-}

-- | Try to build a signature from a bytearray
signature :: ByteArrayAccess ba => ba -> CryptoFailable Signature
signature bs
    | B.length bs == signatureSize =
        CryptoPassed $ Signature $ B.copyAndFreeze bs (\_ -> return ())
    | otherwise =
        CryptoFailed CryptoError_SecretKeyStructureInvalid

-- | Create a public key from a secret key
toPublic :: SecretKey -> PublicKey
toPublic (SecretKey sec) = PublicKey <$>
    B.allocAndFreeze publicKeySize $ \result ->
    withByteArray sec              $ \psec   ->
        ccrypton_ed25519_publickey psec result
{-# NOINLINE toPublic #-}

-- | Sign a message using the key pair
sign :: ByteArrayAccess ba => SecretKey -> PublicKey -> ba -> Signature
sign secret public message =
    Signature $ B.allocAndFreeze signatureSize $ \sig ->
        withByteArray secret  $ \sec ->
        withByteArray public  $ \pub ->
        withByteArray message $ \msg ->
             ccrypton_ed25519_sign msg (fromIntegral msgLen) sec pub sig
  where
    !msgLen = B.length message

-- | Verify a message
verify :: ByteArrayAccess ba => PublicKey -> ba -> Signature -> Bool
verify public message signatureVal = unsafeDoIO $
    withByteArray signatureVal $ \sig ->
    withByteArray public       $ \pub ->
    withByteArray message      $ \msg -> do
      r <- ccrypton_ed25519_sign_open msg (fromIntegral msgLen) pub sig
      return (r == 0)
  where
    !msgLen = B.length message

-- | Sign a message using the key pair
signLazy :: SecretKey -> PublicKey -> L.ByteString -> Signature
signLazy secret public message =
    Signature $ B.allocAndFreeze signatureSize $ \sig ->
        withByteArray secret $ \sec ->
        withByteArray public $ \pub ->
        withChunks $ \chunks lengths -> do
            -- print (chunks, lengths, nChunks)
            -- peekArray nChunks chunks >>= print
            -- peekArray nChunks lengths >>= print
            ccrypton_ed25519_sign_chunks chunks lengths (fromIntegral nChunks) sec pub sig
  where
    nChunks = L.foldlChunks (\n _c -> n + 1) 0 message
    withChunks :: (Ptr (Ptr Word8) -> Ptr CSize -> IO ()) -> IO ()
    withChunks f =
        allocaArray nChunks $ \chunksPtr ->
        allocaArray nChunks $ \lengthsPtr ->
        go chunksPtr lengthsPtr (f chunksPtr lengthsPtr) (L.toChunks message)
    go _cp _lp f' [] = f'
    go cp lp f' (c : cs) =
        withByteArray c $ \cptr -> do
            poke cp cptr
            poke lp (fromIntegral $ B.length c)
            go (cp `plusPtr` ptrSize) (lp `plusPtr` intSize) f' cs
    ptrSize = sizeOf (undefined :: Ptr (Ptr Word8))
    intSize = sizeOf (undefined :: CSize)

-- | Generate a secret key
generateSecretKey :: MonadRandom m => m SecretKey
generateSecretKey = SecretKey <$> getRandomBytes secretKeySize

-- | A public key is 32 bytes
publicKeySize :: Int
publicKeySize = 32

-- | A secret key is 32 bytes
secretKeySize :: Int
secretKeySize = 32

-- | A signature is 64 bytes
signatureSize :: Int
signatureSize = 64

foreign import ccall "crypton_ed25519_publickey"
    ccrypton_ed25519_publickey :: Ptr SecretKey -- secret key
                                  -> Ptr PublicKey -- public key
                                  -> IO ()

foreign import ccall "crypton_ed25519_sign_open"
    ccrypton_ed25519_sign_open :: Ptr Word8     -- message
                                  -> CSize         -- message len
                                  -> Ptr PublicKey -- public
                                  -> Ptr Signature -- signature
                                  -> IO CInt

foreign import ccall "crypton_ed25519_sign"
    ccrypton_ed25519_sign :: Ptr Word8     -- message
                             -> CSize         -- message len
                             -> Ptr SecretKey -- secret
                             -> Ptr PublicKey -- public
                             -> Ptr Signature -- signature
                             -> IO ()

foreign import ccall "crypton_ed25519_sign_chunks"
    ccrypton_ed25519_sign_chunks :: Ptr (Ptr Word8)  -- message chunks
                                    -> Ptr CSize     -- chunk lengths
                                    -> CSize         -- number of chunks
                                    -> Ptr SecretKey -- secret
                                    -> Ptr PublicKey -- public
                                    -> Ptr Signature -- signature
                                    -> IO ()

foreign import ccall "crypton_ed25519_sign_open_chunks"
    ccrypton_ed25519_sign_open_chunks :: Ptr (Ptr Word8) -- message chunks
                                    -> Ptr CSize         -- chunk lengths
                                    -> CSize             -- number of chunks
                                    -> Ptr PublicKey     -- public
                                    -> Ptr Signature     -- signature
                                    -> IO CInt
