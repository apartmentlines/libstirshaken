#include <stir_shaken.h>

const char *path = "./test/run";
const char *x5u = "https://not.here.org/div-passport.cer";
const char *origtn = "12155551212";
const char *old_desttn = "12155551213";
const char *new_desttn = "12155551214";

static int str_contains(const char *haystack, const char *needle)
{
	return haystack && needle && strstr(haystack, needle);
}

stir_shaken_status_t stir_shaken_unit_test_div_passport(void)
{
	stir_shaken_context_t ss = { 0 };
	EC_KEY *ec_key = NULL;
	EVP_PKEY *private_key = NULL;
	EVP_PKEY *public_key = NULL;
	unsigned char priv_raw[STIR_SHAKEN_PRIV_KEY_RAW_BUF_LEN] = { 0 };
	unsigned char pub_raw[STIR_SHAKEN_PUB_KEY_RAW_BUF_LEN] = { 0 };
	uint32_t priv_raw_len = STIR_SHAKEN_PRIV_KEY_RAW_BUF_LEN;
	int pub_raw_len = STIR_SHAKEN_PUB_KEY_RAW_BUF_LEN;
	char private_key_name[300] = { 0 };
	char public_key_name[300] = { 0 };
	const char *dest_vals[1] = { new_desttn };
	const char *multi_dest_vals[2] = { new_desttn, "12155551215" };
	stir_shaken_div_passport_params_t div_params = { 0 };
	stir_shaken_div_passport_params_t compat_params = { 0 };
	stir_shaken_div_passport_params_t from_sih_params = { 0 };
	stir_shaken_passport_params_t shaken_params = { 0 };
	stir_shaken_passport_t *div_passport = NULL;
	stir_shaken_passport_t *compat_passport = NULL;
	stir_shaken_passport_t *shaken_passport = NULL;
	stir_shaken_passport_t *multi_original_passport = NULL;
	stir_shaken_passport_t *from_sih_passport = NULL;
	stir_shaken_passport_t *verified_passport = NULL;
	jwt_t *multi_original_jwt = NULL;
	char *div_sih = NULL;
	char *compat_sih = NULL;
	char *shaken_sih = NULL;
	char *multi_original_sih = NULL;
	char *dump = NULL;
	char *copy = NULL;
	char *token = NULL;
	char *parsed_token = NULL;
	stir_shaken_status_t status = STIR_SHAKEN_STATUS_FALSE;

	sprintf(private_key_name, "%s%c%s", path, '/', "u19_private_key.pem");
	sprintf(public_key_name, "%s%c%s", path, '/', "u19_public_key.pem");

	stir_shaken_generate_keys(&ss, &ec_key, &private_key, &public_key, private_key_name, public_key_name, priv_raw, &priv_raw_len);
	stir_shaken_pubkey_to_raw(&ss, public_key, pub_raw, &pub_raw_len);

	div_params.x5u = x5u;
	div_params.orig_key = "tn";
	div_params.orig_val = origtn;
	div_params.dest_key = "tn";
	div_params.dest_vals = dest_vals;
	div_params.dest_vals_count = 1;
	div_params.div_key = "tn";
	div_params.div_val = old_desttn;
	div_params.iat = 1443208345;

	status = stir_shaken_div_authenticate_keep_passport(&ss, &div_sih, &div_params, priv_raw, priv_raw_len, &div_passport);
	stir_shaken_assert(status == STIR_SHAKEN_STATUS_OK, "Failed to create DIV SIP Identity Header");
	stir_shaken_assert(div_sih, "DIV SIP Identity Header missing");
	stir_shaken_assert(str_contains(div_sih, ";info=<https://not.here.org/div-passport.cer>;alg=ES256;ppt=div"), "DIV SIH did not contain expected params");
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_div_passport_validate_headers_and_grants(&ss, div_passport), "DIV PASSporT validation failed");

	dump = stir_shaken_passport_dump_str(&ss, div_passport, 0);
	stir_shaken_assert(dump, "DIV PASSporT dump missing");
	stir_shaken_assert(str_contains(dump, "\"ppt\":\"div\""), "DIV PASSporT header missing ppt=div");
	stir_shaken_assert(str_contains(dump, "\"dest\":{\"tn\":[\"12155551214\"]}"), "DIV PASSporT payload missing forwarded destination");
	stir_shaken_assert(str_contains(dump, "\"div\":{\"tn\":\"12155551213\"}"), "DIV PASSporT payload missing div claim");
	stir_shaken_assert(!strstr(dump, "\"attest\""), "Strict DIV PASSporT must not include attest");
	stir_shaken_assert(!strstr(dump, "\"origid\""), "Strict DIV PASSporT must not include origid");
	stir_shaken_assert(!strstr(dump, "\"reason\""), "Strict DIV PASSporT must not include reason");
	stir_shaken_free_jwt_str(dump);
	dump = NULL;

	parsed_token = strdup(div_sih);
	stir_shaken_assert(parsed_token, "Out of memory");
	token = strchr(parsed_token, ';');
	stir_shaken_assert(token, "Malformed DIV SIH");
	*token = '\0';
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_sih_verify_with_key(&ss, div_sih, pub_raw, pub_raw_len, &verified_passport), "DIV signature verification failed");
	stir_shaken_passport_destroy(&verified_passport);
	free(parsed_token);
	parsed_token = NULL;

	compat_params = div_params;
	compat_params.reason = "forwarding";
	compat_params.attest = "A";
	compat_params.origid = "orig-id-1";
	compat_params.flags = STIR_SHAKEN_DIV_FLAG_INCLUDE_REASON | STIR_SHAKEN_DIV_FLAG_INCLUDE_SHAKEN_CLAIMS;
	status = stir_shaken_div_authenticate_keep_passport(&ss, &compat_sih, &compat_params, priv_raw, priv_raw_len, &compat_passport);
	stir_shaken_assert(status == STIR_SHAKEN_STATUS_OK, "Failed to create compatibility DIV SIP Identity Header");
	dump = stir_shaken_passport_dump_str(&ss, compat_passport, 0);
	stir_shaken_assert(dump, "Compatibility DIV PASSporT dump missing");
	stir_shaken_assert(str_contains(dump, "\"attest\":\"A\""), "Compatibility DIV PASSporT missing attest");
	stir_shaken_assert(str_contains(dump, "\"origid\":\"orig-id-1\""), "Compatibility DIV PASSporT missing origid");
	stir_shaken_assert(str_contains(dump, "\"reason\":\"forwarding\""), "Compatibility DIV PASSporT missing reason");
	stir_shaken_free_jwt_str(dump);
	dump = NULL;

	shaken_params.x5u = x5u;
	shaken_params.attest = "A";
	shaken_params.desttn_key = "tn";
	shaken_params.desttn_val = old_desttn;
	shaken_params.iat = 1443208345;
	shaken_params.origtn_key = "tn";
	shaken_params.origtn_val = origtn;
	shaken_params.origid = "orig-id-1";
	status = stir_shaken_jwt_authenticate_keep_passport(&ss, &shaken_sih, &shaken_params, priv_raw, priv_raw_len, &shaken_passport);
	stir_shaken_assert(status == STIR_SHAKEN_STATUS_OK, "Failed to create original SHAKEN SIH");
	stir_shaken_assert(str_contains(shaken_sih, "ppt=shaken"), "Original SHAKEN SIH did not contain ppt=shaken");
	copy = strdup(shaken_sih);
	stir_shaken_assert(copy, "Out of memory");

	status = stir_shaken_div_params_from_original_sih(&ss, shaken_sih, x5u, "tn", dest_vals, 1, NULL, NULL, 0, &from_sih_params);
	stir_shaken_assert(status == STIR_SHAKEN_STATUS_OK, "Failed to build DIV params from SHAKEN SIH");
	stir_shaken_assert(!strcmp(copy, shaken_sih), "Original SHAKEN SIH was mutated");
	free(div_sih);
	div_sih = NULL;
	status = stir_shaken_div_authenticate_keep_passport(&ss, &div_sih, &from_sih_params, priv_raw, priv_raw_len, &from_sih_passport);
	stir_shaken_assert(status == STIR_SHAKEN_STATUS_OK, "Failed to create DIV SIH from extracted params");
	dump = stir_shaken_passport_dump_str(&ss, from_sih_passport, 0);
	stir_shaken_assert(str_contains(dump, "\"orig\":{\"tn\":\"12155551212\"}"), "Extracted DIV PASSporT missing original orig");
	stir_shaken_assert(str_contains(dump, "\"div\":{\"tn\":\"12155551213\"}"), "Extracted DIV PASSporT missing selected div");
	stir_shaken_free_jwt_str(dump);
	dump = NULL;

	stir_shaken_div_passport_params_destroy(&from_sih_params);
	status = stir_shaken_div_params_from_original_sih(&ss, shaken_sih, x5u, "tn", multi_dest_vals, 2, NULL, NULL, 0, &from_sih_params);
	stir_shaken_assert(status == STIR_SHAKEN_STATUS_OK, "Multiple new forwarded destinations should be allowed");
	stir_shaken_div_passport_params_destroy(&from_sih_params);

	multi_original_jwt = stir_shaken_passport_jwt_create_new(&ss);
	stir_shaken_assert(multi_original_jwt, "Failed to create multi-destination original JWT");
	status = stir_shaken_passport_jwt_init_from_json(
		&ss,
		multi_original_jwt,
		"{\"ppt\":\"shaken\",\"typ\":\"passport\",\"x5u\":\"https://not.here.org/div-passport.cer\"}",
		"{\"attest\":\"A\",\"dest\":{\"tn\":[\"12155551213\",\"12155551216\"]},\"iat\":1443208345,\"orig\":{\"tn\":\"12155551212\"},\"origid\":\"orig-id-1\"}",
		priv_raw,
		priv_raw_len);
	stir_shaken_assert(status == STIR_SHAKEN_STATUS_OK, "Failed to initialize multi-destination original JWT");
	multi_original_passport = stir_shaken_passport_create(&ss, NULL, NULL, 0);
	stir_shaken_assert(multi_original_passport, "Failed to create multi-destination original PASSporT");
	stir_shaken_jwt_move_to_passport(&ss, multi_original_jwt, multi_original_passport);
	multi_original_jwt = NULL;
	multi_original_sih = stir_shaken_jwt_sip_identity_create(&ss, multi_original_passport, NULL, 0);
	stir_shaken_assert(multi_original_sih, "Failed to create multi-destination original SIH");
	status = stir_shaken_div_params_from_original_sih(&ss, multi_original_sih, x5u, "tn", dest_vals, 1, NULL, NULL, 0, &from_sih_params);
	stir_shaken_assert(status != STIR_SHAKEN_STATUS_OK, "Original SIH with multiple destinations must require explicit selection");
	stir_shaken_div_passport_params_destroy(&from_sih_params);
	status = stir_shaken_div_params_from_original_sih(&ss, multi_original_sih, x5u, "tn", dest_vals, 1, "tn", old_desttn, 0, &from_sih_params);
	stir_shaken_assert(status == STIR_SHAKEN_STATUS_OK, "Explicit original destination selection should work");
	stir_shaken_div_passport_params_destroy(&from_sih_params);

	free(copy);
	copy = NULL;
	free(div_sih);
	div_sih = NULL;
	free(compat_sih);
	compat_sih = NULL;
	free(shaken_sih);
	shaken_sih = NULL;
	free(multi_original_sih);
	multi_original_sih = NULL;
	stir_shaken_passport_destroy(&div_passport);
	stir_shaken_passport_destroy(&compat_passport);
	stir_shaken_passport_destroy(&shaken_passport);
	stir_shaken_passport_destroy(&multi_original_passport);
	stir_shaken_passport_destroy(&from_sih_passport);
	if (multi_original_jwt) jwt_free(multi_original_jwt);
	stir_shaken_destroy_keys_ex(&ec_key, &private_key, &public_key);

	return STIR_SHAKEN_STATUS_OK;
}

int main(void)
{
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_init(NULL, STIR_SHAKEN_LOGLEVEL_NOTHING), "Cannot init lib");

	if (stir_shaken_dir_exists(path) != STIR_SHAKEN_STATUS_OK && stir_shaken_dir_create_recursive(path) != STIR_SHAKEN_STATUS_OK) {
		printf("ERR: Cannot create test dir\n");
		return -1;
	}

	if (stir_shaken_unit_test_div_passport() != STIR_SHAKEN_STATUS_OK) {
		printf("Fail\n");
		return -2;
	}

	stir_shaken_deinit();
	printf("OK\n");
	return 0;
}
