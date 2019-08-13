//This Source Code Form is subject to the terms of the Mozilla Public
//License, v. 2.0. If a copy of the MPL was not distributed with this
//file, You can obtain one at https://mozilla.org/MPL/2.0/.

// © 2019 Aditya Kishore

import 'dart:typed_data';
import 'dart:convert';

part 'binhex.dart';

/// Implements Chacha20 ([https://tools.ietf.org/html/rfc7539](RFC 7539)), which
/// has become a popular symmetric stream cipher. It's now used by protocols
/// such as TLS.

class Chacha20 extends Converter<List<int>, Uint8List> {
  // Some constants
  static const int keyLengthInBytes = 32;
  static const int nonceLengthInBytes = 12;
  static const int _stateLength = 16;

  // Static buffers.
  //
  // They are cleared after every operation so sensitive data
  // will not remain in the heap.

  static final Uint32List _state = Uint32List(_stateLength);
  static final ByteData _stateByteData = ByteData.view(
    _state.buffer,
    _state.offsetInBytes,
    _state.lengthInBytes,
  );


  // Initialization
  final Uint32List initialState = Uint32List(_stateLength);

  /// Sets initial state using the key, nonce, and counter.
  void initialize({
    List<int> key,
    List<int> nonce,
    int keyStreamIndex = 0,
  }) {
    if (key == null) {
      throw ArgumentError.notNull("key");
    }

    // Mark as uninitialized so encryption will fail if this method throws.
    final state = this.initialState;
    state[0] = 0;

    // Key
    this.setKeyBytes(key);

    // Counter
    this.keyStreamIndex = keyStreamIndex;

    // Nonce
    this.setNonceBytes(nonce);

    // Finally, set constants
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;
  }

  int _keyStreamIndex = 0;

  int get keyStreamIndex => _keyStreamIndex;

  set keyStreamIndex(int value) {
    this._keyStreamIndex = value;
    this.initialState[12] = value ~/ 64;
  }

  /// Sets the 256-bit Chacha20 key using the bytes.
  void setKeyBytes(List<int> key) {
    if (key == null) {
      throw ArgumentError.notNull("key");
    }
    if (key.length != keyLengthInBytes) {
      throw ArgumentError.value(
        key,
        "key",
        "length is ${key.length}, should be ${keyLengthInBytes}",
      );
    }

    final state = this.initialState;
    final stateByteData = ByteData.view(
      state.buffer,
      state.offsetInBytes,
      state.lengthInBytes,
    );

    int stateBytesIndex = 4 * 4;
    for (var i = 0; i < key.length; i++) {
      stateByteData.setUint8(stateBytesIndex, key[i]);
      stateBytesIndex++;
    }

    // Convert little endian --> host endian
    for (var i = 4; i < 12; i++) {
      state[i] = stateByteData.getUint32(4 * i, Endian.little);
    }
  }

  /// Sets the 96-bit Chacha20 nonce using the bytes.
  /// If the argument is null, zeroes will be used.
  void setNonceBytes(List<int> nonce) {
    if (nonce == null) {
      for (var i = 13; i < 16; i++) {
        initialState[i] = 0;
      }
      return;
    }
    if (nonce.length != nonceLengthInBytes) {
      throw ArgumentError.value(
        nonce,
        "nonce",
        "length is ${nonce.length}, should be ${nonceLengthInBytes}",
      );
    }

    final state = this.initialState;
    final stateByteData = ByteData.view(
      state.buffer,
      state.offsetInBytes,
      state.lengthInBytes,
    );

    var stateBytesIndex = 13 * 4;
    for (var i = 0; i < nonce.length; i++) {
      stateByteData.setUint8(stateBytesIndex, nonce[i]);
      stateBytesIndex++;
    }

    // Convert little endian --> host endian
    for (var i = 13; i < 16; i++) {
      state[i] = stateByteData.getUint32(4 * i, Endian.little);
    }
  }

  /// After invoking this method, encryption operations will fail unless
  /// [initialize] is called.
  void clear() {
    initialState.fillRange(0, initialState.length, 0);
  }

  Uint8List convert(List<int> input) {
    final result = Uint8List(input.length);
    fillWithConverted(result, 0, input, 0);
    return result;
  }

  // Other methods

  /// Fills the list with converted bytes.
  ///
  /// Throws [StateError] if [initialize] has not been invoked or [clear] has
  /// been invoked.
  void fillWithConverted(
      List<int> result, int resultStart, List<int> input, int inputStart,
      {int length}) {
    if (length == null) {
      length = result.length - resultStart;
      final inputLength = input.length - inputStart;
      if (inputLength < length) {
        length = inputLength;
      }
    }

    // Fill result with key stream
    fillWithKeyStream(result, resultStart, length: length);

    // XOR
    for (var i = 0; i < length; i++) {
      result[resultStart + i] ^= input[inputStart + i];
    }
  }

  /// Fills the list with key stream bytes.
  ///
  /// Throws [StateError] if [initialize] has not been invoked or [clear] has
  /// been invoked.
  void fillWithKeyStream(List<int> result, int start, {int length}) {
    if (start < 0) {
      throw ArgumentError.value(start, "start");
    }
    if (length == null) {
      length = result.length - start;
    } else if (length < 0 || length > result.length - start) {
      throw ArgumentError.value(length, "length");
    }
    _validateInitialState(initialState);

    // Special case for empty lists
    if (length == 0) {
      return;
    }

    // Declare variables
    final state = _state;
    final stateByteData = _stateByteData;
    var keyStreamIndex = this.keyStreamIndex;

    // Prepare for optimized copying
    //
    // For key streams over 256 bytes:
    // Whole blocks will be copied using 16 uint32 assignments
    // (including host endian to little endian conversion).
    //
    // Benchmarks indicated this has a surprisingly high (>30%) impact
    // on converting long streams.
    //
    // Minimum length 256 bytes is just a guess of a good value.
    ByteData resultByteData;
    if (length > 256 && keyStreamIndex % 64 == 0 && result is Uint8List) {
      resultByteData = ByteData.view(
        result.buffer,
        result.offsetInBytes,
        result.lengthInBytes,
      );
    }

    try {
      // For each byte
      while (length > 0) {
        // Encrypt state
        encryptState(state);

        // Should we copy
        if (resultByteData != null && length >= 64) {
          // Copy whole block using 16 uint32 assignments
          for (var i = 0; i < 16; i++) {
            resultByteData.setUint32(start, state[i], Endian.little);
            start += 4;
          }

          // Increment variables
          keyStreamIndex += 64;
          length -= 64;
        } else {
          // Byte-by-byte method

          // Convert state:
          // Host endian --> little endian
          for (var i = 0; i < state.length; i++) {
            stateByteData.setUint32(4 * i, state[i], Endian.little);
          }

          // Do uint8 assignments
          for (var i = keyStreamIndex % 64; i < 64 && length > 0; i++) {
            result[start] = stateByteData.getUint8(i);

            // Increment key stream index
            keyStreamIndex++;
            length--;
            start++;
          }
        }

        // Store current 'keyStreamIndex'
        this.keyStreamIndex = keyStreamIndex;
      }
    } finally {
      // Clear static state buffer.
      // This is not strictly necessary, but it's good for data protection.
      for (var i = 0; i < state.length; i++) {
        state[i] = 0;
      }
    }
  }

  // Internal methods

  static void _validateInitialState(Uint32List initialState) {
    if (initialState[0] != 0x61707865) {
      throw StateError(
          "Initial state is invalid. Did you forget to call 'initialize'?");
    }
  }

  /// Chacha20 state encryption algorithm. Used by [fillWithKeyStream].
  ///
  /// Throws [StateError] if [initialize] has not been invoked or [clear] has
  /// been invoked.
  void encryptState(Uint32List state) {
    // Validate that we have a proper initial state.
    _validateInitialState(initialState);

    // Step 1: Initialize
    var v0 = initialState[0],
        v1 = initialState[1],
        v2 = initialState[2],
        v3 = initialState[3],
        v4 = initialState[4],
        v5 = initialState[5],
        v6 = initialState[6],
        v7 = initialState[7],
        v8 = initialState[8],
        v9 = initialState[9],
        v10 = initialState[10],
        v11 = initialState[11],
        v12 = initialState[12],
        v13 = initialState[13],
        v14 = initialState[14],
        v15 = initialState[15];

    // Step 2: Do 20 column/diagonal rounds
    for (var i = 0; i < 10; i++) {

      // Columns
      v0 = _uint32mask & (v0 + v4);
      v12 = _rotateLeft(v12 ^ v0, 16);
      v8 = _uint32mask & (v8 + v12);
      v4 = _rotateLeft(v4 ^ v8, 12);
      v0 = _uint32mask & (v0 + v4);
      v12 = _rotateLeft(v12 ^ v0, 8);
      v8 = _uint32mask & (v8 + v12);
      v4 = _rotateLeft(v4 ^ v8, 7);

      v1 = _uint32mask & (v1 + v5);
      v13 = _rotateLeft(v13 ^ v1, 16);
      v9 = _uint32mask & (v9 + v13);
      v5 = _rotateLeft(v5 ^ v9, 12);
      v1 = _uint32mask & (v1 + v5);
      v13 = _rotateLeft(v13 ^ v1, 8);
      v9 = _uint32mask & (v9 + v13);
      v5 = _rotateLeft(v5 ^ v9, 7);

      v2 = _uint32mask & (v2 + v6);
      v14 = _rotateLeft(v14 ^ v2, 16);
      v10 = _uint32mask & (v10 + v14);
      v6 = _rotateLeft(v6 ^ v10, 12);
      v2 = _uint32mask & (v2 + v6);
      v14 = _rotateLeft(v14 ^ v2, 8);
      v10 = _uint32mask & (v10 + v14);
      v6 = _rotateLeft(v6 ^ v10, 7);

      v3 = _uint32mask & (v3 + v7);
      v15 = _rotateLeft(v15 ^ v3, 16);
      v11 = _uint32mask & (v11 + v15);
      v7 = _rotateLeft(v7 ^ v11, 12);
      v3 = _uint32mask & (v3 + v7);
      v15 = _rotateLeft(v15 ^ v3, 8);
      v11 = _uint32mask & (v11 + v15);
      v7 = _rotateLeft(v7 ^ v11, 7);

      // Diagonals
      v0 = _uint32mask & (v0 + v5);
      v15 = _rotateLeft(v15 ^ v0, 16);
      v10 = _uint32mask & (v10 + v15);
      v5 = _rotateLeft(v5 ^ v10, 12);
      v0 = _uint32mask & (v0 + v5);
      v15 = _rotateLeft(v15 ^ v0, 8);
      v10 = _uint32mask & (v10 + v15);
      v5 = _rotateLeft(v5 ^ v10, 7);

      v1 = _uint32mask & (v1 + v6);
      v12 = _rotateLeft(v12 ^ v1, 16);
      v11 = _uint32mask & (v11 + v12);
      v6 = _rotateLeft(v6 ^ v11, 12);
      v1 = _uint32mask & (v1 + v6);
      v12 = _rotateLeft(v12 ^ v1, 8);
      v11 = _uint32mask & (v11 + v12);
      v6 = _rotateLeft(v6 ^ v11, 7);

      v2 = _uint32mask & (v2 + v7);
      v13 = _rotateLeft(v13 ^ v2, 16);
      v8 = _uint32mask & (v8 + v13);
      v7 = _rotateLeft(v7 ^ v8, 12);
      v2 = _uint32mask & (v2 + v7);
      v13 = _rotateLeft(v13 ^ v2, 8);
      v8 = _uint32mask & (v8 + v13);
      v7 = _rotateLeft(v7 ^ v8, 7);

      v3 = _uint32mask & (v3 + v4);
      v14 = _rotateLeft(v14 ^ v3, 16);
      v9 = _uint32mask & (v9 + v14);
      v4 = _rotateLeft(v4 ^ v9, 12);
      v3 = _uint32mask & (v3 + v4);
      v14 = _rotateLeft(v14 ^ v3, 8);
      v9 = _uint32mask & (v9 + v14);
      v4 = _rotateLeft(v4 ^ v9, 7);
    }

    // Step 3: Addition
    state[0] = _uint32mask & (v0 + initialState[0]);
    state[1] = _uint32mask & (v1 + initialState[1]);
    state[2] = _uint32mask & (v2 + initialState[2]);
    state[3] = _uint32mask & (v3 + initialState[3]);
    state[4] = _uint32mask & (v4 + initialState[4]);
    state[5] = _uint32mask & (v5 + initialState[5]);
    state[6] = _uint32mask & (v6 + initialState[6]);
    state[7] = _uint32mask & (v7 + initialState[7]);
    state[8] = _uint32mask & (v8 + initialState[8]);
    state[9] = _uint32mask & (v9 + initialState[9]);
    state[10] = _uint32mask & (v10 + initialState[10]);
    state[11] = _uint32mask & (v11 + initialState[11]);
    state[12] = _uint32mask & (v12 + initialState[12]);
    state[13] = _uint32mask & (v13 + initialState[13]);
    state[14] = _uint32mask & (v14 + initialState[14]);
    state[15] = _uint32mask & (v15 + initialState[15]);
  }
}

/// For ensuring that result of calculation will be 32-bit integer.
const int _uint32mask = 0xFFFFFFFF;

/// Rotates 32-bit integer to the left.
int _rotateLeft(int data, int shift) {
  return _uint32mask & ((data << shift) | (data >> (32 - shift)));
}