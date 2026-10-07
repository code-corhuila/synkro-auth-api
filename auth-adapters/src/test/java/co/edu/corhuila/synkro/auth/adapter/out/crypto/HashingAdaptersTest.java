package co.edu.corhuila.synkro.auth.adapter.out.crypto;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class HashingAdaptersTest {

    @Test
    void sha256_matchesTheKnownVectorForAbc() {
        assertThat(new Sha256HashFunction().hash("abc"))
            .isEqualTo("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    @Test
    void sha256_isDeterministicAndNeverEchoesTheInput() {
        Sha256HashFunction hash = new Sha256HashFunction();

        assertThat(hash.hash("token")).isEqualTo(hash.hash("token"));
        assertThat(hash.hash("token")).isNotEqualTo(hash.hash("token2")).doesNotContain("token");
    }

    @Test
    void bcrypt_hashesWithCostOfAtLeast12_andVerifies() {
        BcryptPasswordHasher hasher = new BcryptPasswordHasher();

        String hash = hasher.hash("s3cret");

        assertThat(hash).matches("\\$2[aby]\\$(1[2-9]|[2-3][0-9])\\$.{53}");
        assertThat(hasher.matches("s3cret", hash)).isTrue();
        assertThat(hasher.matches("other", hash)).isFalse();
    }

    @Test
    void bcrypt_neverThrowsOnAMalformedHash() {
        assertThat(new BcryptPasswordHasher().matches("x", "not-a-bcrypt-hash")).isFalse();
    }
}
