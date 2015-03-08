{-# LANGUAGE ForeignFunctionInterface, CPP, MultiParamTypeClasses #-}

-- |
-- Module      : Crypto.Hash.Internal.SHA1
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- A module containing SHA1 bindings
--
module Crypto.Hash.Internal.SHA1
    ( Ctx(..)
    -- * Internal values
    , digestSize
    , sizeCtx
    -- * Internal IO hash functions
    , internalInit
    , internalInitAt
    , internalUpdate
    , internalUpdateUnsafe
    , internalFinalize
    -- * Context copy and creation
    , withCtxCopy
    , withCtxNewThrow
    , withCtxThrow
    ) where

import Foreign.Ptr
import Data.ByteString (ByteString)
import Data.ByteString.Unsafe (unsafeUseAsCStringLen)
import Data.ByteString.Internal (create)
import Data.Word
import Crypto.Internal.Memory

newtype Ctx = Ctx Bytes

{-# INLINE digestSize #-}
digestSize :: Int
digestSize = 20

{-# INLINE sizeCtx #-}
sizeCtx :: Int
sizeCtx = 96

withCtxCopy :: Ctx -> (Ptr Ctx -> IO ()) -> IO Ctx
withCtxCopy (Ctx b) f = Ctx `fmap` bytesCopyAndModify b f

withCtxThrow :: Ctx -> (Ptr Ctx -> IO a) -> IO a
withCtxThrow (Ctx b) f = bytesCopyTemporary b f

withCtxNewThrow :: (Ptr Ctx -> IO a) -> IO a
withCtxNewThrow f = bytesTemporary 96 f

foreign import ccall unsafe "cryptonite_sha1.h cryptonite_sha1_init"
    c_sha1_init :: Ptr Ctx -> IO ()

foreign import ccall "cryptonite_sha1.h cryptonite_sha1_update"
    c_sha1_update :: Ptr Ctx -> Ptr Word8 -> Word32 -> IO ()

foreign import ccall unsafe "cryptonite_sha1.h cryptonite_sha1_update"
    c_sha1_update_unsafe :: Ptr Ctx -> Ptr Word8 -> Word32 -> IO ()

foreign import ccall unsafe "cryptonite_sha1.h cryptonite_sha1_finalize"
    c_sha1_finalize :: Ptr Ctx -> Ptr Word8 -> IO ()

internalInitAt :: Ptr Ctx -> IO ()
internalInitAt = c_sha1_init

-- | init a context
internalInit :: IO Ctx
internalInit = Ctx `fmap` bytesAlloc 96 internalInitAt

-- | Update a context in place
internalUpdate :: Ptr Ctx -> ByteString -> IO ()
internalUpdate ptr d =
    unsafeUseAsCStringLen d (\(cs, len) -> c_sha1_update ptr (castPtr cs) (fromIntegral len))

-- | Update a context in place using an unsafe foreign function call.
--
-- It is faster than `internalUpdate`, but will block the haskell runtime.
-- This shouldn't be used if the input data is large.
internalUpdateUnsafe :: Ptr Ctx -> ByteString -> IO ()
internalUpdateUnsafe ptr d =
    unsafeUseAsCStringLen d (\(cs, len) -> c_sha1_update_unsafe ptr (castPtr cs) (fromIntegral len))

-- | Finalize a context in place
internalFinalize :: Ptr Ctx -> IO ByteString
internalFinalize ptr = create digestSize (c_sha1_finalize ptr)
