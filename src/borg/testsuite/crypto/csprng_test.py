import pytest

from ...crypto.low_level import CSPRNG


# Test keys (32 bytes each)
key1 = bytes.fromhex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
key2 = bytes.fromhex("fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210")


def test_deterministic_output():
    """Test that the same key produces the same random sequence."""
    # Create two CSPRNGs with the same key
    rng1 = CSPRNG(key1)
    rng2 = CSPRNG(key1)

    # Generate random bytes from both
    bytes1 = rng1.random_bytes(100)
    bytes2 = rng2.random_bytes(100)

    # They should be identical
    assert bytes1 == bytes2

    # Different keys should produce different outputs
    rng3 = CSPRNG(key2)
    bytes3 = rng3.random_bytes(100)
    assert bytes1 != bytes3


def test_random_bytes():
    """Test the random_bytes method."""
    rng = CSPRNG(key1)

    # Test different sizes
    for size in [1, 10, 100, 1000, 10000]:
        random_data = rng.random_bytes(size)

        # Check type
        assert isinstance(random_data, bytes)

        # Check length
        assert len(random_data) == size


def test_random_int():
    """Test the random_int method."""
    rng = CSPRNG(key1)

    # Test different ranges
    for upper_bound in [2, 10, 100, 1000, 1000000, 1000000000, 1000000000000]:
        # Generate multiple random integers
        for _ in range(10):
            random_int = rng.random_int(upper_bound)

            # Check range
            assert 0 <= random_int < upper_bound

            # Check type
            assert isinstance(random_int, int)


def test_random_int_edge_cases():
    """Test the random_int method with edge cases."""
    rng = CSPRNG(key1)

    # Test error case: upper_bound <= 0
    with pytest.raises(ValueError):
        rng.random_int(-1)

    with pytest.raises(ValueError):
        rng.random_int(0)

    # Test with upper bound 1
    assert rng.random_int(1) == 0

    # Test with upper bound 2
    for _ in range(10):
        result = rng.random_int(2)
        assert 0 <= result < 2

    # Test with upper bound that is a power of 2
    power_of_2 = 256
    for _ in range(10):
        result = rng.random_int(power_of_2)
        assert 0 <= result < power_of_2

    # Test with upper bound that is one less than a power of 2
    almost_power_of_2 = 255
    for _ in range(10):
        result = rng.random_int(almost_power_of_2)
        assert 0 <= result < almost_power_of_2

    # Test with upper bound that is one more than a power of 2
    just_over_power_of_2 = 257
    for _ in range(10):
        result = rng.random_int(just_over_power_of_2)
        assert 0 <= result < just_over_power_of_2

    # Test with a large upper bound
    large_bound = 1000000000
    for _ in range(10):
        result = rng.random_int(large_bound)
        assert 0 <= result < large_bound


def test_shuffle():
    """Test the shuffle method."""
    rng1 = CSPRNG(key1)
    rng2 = CSPRNG(key1)

    # Create two identical lists
    list1 = list(range(100))
    list2 = list(range(100))

    # Shuffle both lists with the same key
    rng1.shuffle(list1)
    rng2.shuffle(list2)

    # They should be identical after shuffling
    assert list1 == list2

    # The shuffled list should be a permutation of the original
    assert sorted(list1) == list(range(100))

    # Different keys should produce different shuffles
    rng3 = CSPRNG(key2)
    list3 = list(range(100))
    rng3.shuffle(list3)
    assert list1 != list3

    # Getting another shuffled list by an already used RNG should produce a different shuffle
    list4 = list(range(100))
    rng1.shuffle(list4)
    assert list1 != list4


def test_statistical_properties():
    """Test basic statistical properties of the random output."""
    rng = CSPRNG(key1)

    # Generate a large number of random bytes
    data = rng.random_bytes(10000)

    # Count occurrences of each byte value
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1

    # Check that each byte value appears with roughly equal frequency
    # For 10000 bytes, each value should appear about 39 times (10000/256)
    # We allow a generous margin of error (±50%)
    for count in counts:
        assert 19 <= count <= 59, "Byte distribution is not uniform"

    # Test bit distribution
    bits_set = 0
    for byte in data:
        bits_set += bin(byte).count("1")

    # For random data, approximately 50% of bits should be set
    # 10000 bytes = 80000 bits, so about 40000 should be set
    # Allow ±5% margin
    assert 38000 <= bits_set <= 42000, "Bit distribution is not uniform"


def test_large_shuffle():
    """Test shuffling a large list."""
    rng = CSPRNG(key1)

    # Create a large list
    large_list = list(range(10000))

    # Make a copy for comparison
    original = large_list.copy()

    # Shuffle the list
    rng.shuffle(large_list)

    # The shuffled list should be different from the original
    assert large_list != original

    # The shuffled list should be a permutation of the original
    assert sorted(large_list) == original
