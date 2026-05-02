#include "stir_shaken.h"

static int stir_shaken_header_value_is_safe(const char *s)
{
	if (!s) return 1;
	return !strchr(s, '\r') && !strchr(s, '\n');
}

static const char *stir_shaken_identity_key_or_default(const char *key)
{
	return stir_shaken_zstr(key) ? "tn" : key;
}

static stir_shaken_status_t stir_shaken_validate_identity_key(stir_shaken_context_t *ss, const char *key)
{
	if (stir_shaken_zstr(key)) return STIR_SHAKEN_STATUS_OK;
	if (!strcmp(key, "tn") || !strcmp(key, "uri")) return STIR_SHAKEN_STATUS_OK;

	stir_shaken_set_error(ss, "Identity key must be 'tn' or 'uri'", STIR_SHAKEN_ERROR_BAD_PARAMS_1);
	return STIR_SHAKEN_STATUS_FALSE;
}

static stir_shaken_status_t stir_shaken_validate_attest(stir_shaken_context_t *ss, const char *attest)
{
	if (!attest || !((*attest == 'A' || *attest == 'B' || *attest == 'C') && attest[1] == '\0')) {
		stir_shaken_set_error(ss, "DIV PASSporT @attest must be 'A', 'B' or 'C'", STIR_SHAKEN_ERROR_PASSPORT_ATTEST_VALUE);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	return STIR_SHAKEN_STATUS_OK;
}

static stir_shaken_status_t stir_shaken_json_get_string_dup(stir_shaken_context_t *ss, ks_json_t *obj, const char *key, char **out)
{
	ks_json_t *item = NULL;
	const char *value = NULL;
	int num = 0;

	if (!obj || !key || !out) return STIR_SHAKEN_STATUS_TERM;

	item = ks_json_get_object_item(obj, key);
	if (!item) return STIR_SHAKEN_STATUS_FALSE;

	if (ks_json_type_get(item) == KS_JSON_TYPE_STRING) {
#if KS_VERSION_NUM >= 20000
		ks_json_value_string(item, &value);
#else
		value = ks_json_value_string(item);
#endif
		if (stir_shaken_zstr(value)) return STIR_SHAKEN_STATUS_FALSE;
		*out = strdup(value);
	} else if (ks_json_type_get(item) == KS_JSON_TYPE_NUMBER) {
#if KS_VERSION_NUM >= 20000
		ks_json_value_number_int(item, &num);
#else
		num = ks_json_value_number_int(item);
#endif
		*out = malloc(20);
		if (*out) snprintf(*out, 20, "%d", num);
	} else {
		return STIR_SHAKEN_STATUS_FALSE;
	}

	if (!*out) {
		stir_shaken_set_error(ss, "Out of memory", STIR_SHAKEN_ERROR_MEM_ID);
		return STIR_SHAKEN_STATUS_TERM;
	}

	return STIR_SHAKEN_STATUS_OK;
}

static stir_shaken_status_t stir_shaken_json_get_identity_dup(stir_shaken_context_t *ss, ks_json_t *obj, char **key_out, char **val_out)
{
	char *val = NULL;
	const char *key = NULL;

	if (!obj || !key_out || !val_out) return STIR_SHAKEN_STATUS_TERM;

	if (ks_json_type_get(obj) == KS_JSON_TYPE_ARRAY) {
		obj = ks_json_get_array_item(obj, 0);
		if (!obj) {
			stir_shaken_set_error(ss, "Identity array is empty", STIR_SHAKEN_ERROR_PASSPORT_ARRAY_ITEM);
			return STIR_SHAKEN_STATUS_FALSE;
		}
	}

	if (STIR_SHAKEN_STATUS_OK == stir_shaken_json_get_string_dup(ss, obj, "tn", &val)) {
		key = "tn";
	} else if (STIR_SHAKEN_STATUS_OK == stir_shaken_json_get_string_dup(ss, obj, "uri", &val)) {
		key = "uri";
	} else {
		stir_shaken_set_error(ss, "Identity object has neither @tn nor @uri", STIR_SHAKEN_ERROR_PASSPORT_ORIG_FORM);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	*key_out = strdup(key);
	if (!*key_out) {
		free(val);
		stir_shaken_set_error(ss, "Out of memory", STIR_SHAKEN_ERROR_MEM_ID);
		return STIR_SHAKEN_STATUS_TERM;
	}
	*val_out = val;
	return STIR_SHAKEN_STATUS_OK;
}

static stir_shaken_status_t stir_shaken_json_add_identity_object(stir_shaken_context_t *ss, ks_json_t *parent, const char *name, const char *key, const char *val)
{
	ks_json_t *obj = NULL;

	if (stir_shaken_zstr(val)) {
		stir_shaken_set_error(ss, "Identity value missing", STIR_SHAKEN_ERROR_BAD_PARAMS_2);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	obj = ks_json_create_object();
	if (!obj) {
		stir_shaken_set_error(ss, "Failed to create identity JSON object", STIR_SHAKEN_ERROR_KSJSON_CREATE_OBJECT_JSON_1);
		return STIR_SHAKEN_STATUS_ERR;
	}

	key = stir_shaken_identity_key_or_default(key);
#if KS_VERSION_NUM >= 20000
	ks_json_add_string_to_object(obj, key, val);
	ks_json_add_item_to_object(parent, name, obj);
#else
	if (!ks_json_add_string_to_object(obj, key, val) || !ks_json_add_item_to_object(parent, name, obj)) {
		ks_json_delete(&obj);
		stir_shaken_set_error(ss, "Failed to add identity JSON object", STIR_SHAKEN_ERROR_KSJSON_ADD_TN);
		return STIR_SHAKEN_STATUS_ERR;
	}
#endif

	return STIR_SHAKEN_STATUS_OK;
}

static stir_shaken_status_t stir_shaken_json_add_dest_object(stir_shaken_context_t *ss, ks_json_t *parent, const char *key, const char **vals, uint32_t vals_count)
{
	ks_json_t *dest = NULL;
	ks_json_t *arr = NULL;
	uint32_t i = 0;

	if (!vals || vals_count == 0) {
		stir_shaken_set_error(ss, "Destination value missing", STIR_SHAKEN_ERROR_BAD_PARAMS_3);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	dest = ks_json_create_object();
	arr = ks_json_create_array();
	if (!dest || !arr) {
		if (dest) ks_json_delete(&dest);
		if (arr) ks_json_delete(&arr);
		stir_shaken_set_error(ss, "Failed to create dest JSON", STIR_SHAKEN_ERROR_KSJSON_CREATE_OBJECT_DEST);
		return STIR_SHAKEN_STATUS_ERR;
	}

	for (i = 0; i < vals_count; i++) {
		if (stir_shaken_zstr(vals[i])) {
			ks_json_delete(&arr);
			ks_json_delete(&dest);
			stir_shaken_set_error(ss, "Destination value missing", STIR_SHAKEN_ERROR_BAD_PARAMS_4);
			return STIR_SHAKEN_STATUS_FALSE;
		}
#if KS_VERSION_NUM >= 20000
		ks_json_add_string_to_array(arr, vals[i]);
#else
		if (!ks_json_add_string_to_array(arr, vals[i])) {
			ks_json_delete(&arr);
			ks_json_delete(&dest);
			stir_shaken_set_error(ss, "Failed to add destination value", STIR_SHAKEN_ERROR_KSJSON_ADD_DEST_TO_ARRAY);
			return STIR_SHAKEN_STATUS_ERR;
		}
#endif
	}

	key = stir_shaken_identity_key_or_default(key);
#if KS_VERSION_NUM >= 20000
	ks_json_add_item_to_object(dest, key, arr);
	ks_json_add_item_to_object(parent, "dest", dest);
#else
	if (!ks_json_add_item_to_object(dest, key, arr) || !ks_json_add_item_to_object(parent, "dest", dest)) {
		ks_json_delete(&arr);
		ks_json_delete(&dest);
		stir_shaken_set_error(ss, "Failed to build dest JSON", STIR_SHAKEN_ERROR_KSJSON_ADD_DEST_ARRAY);
		return STIR_SHAKEN_STATUS_ERR;
	}
#endif

	return STIR_SHAKEN_STATUS_OK;
}

static stir_shaken_status_t stir_shaken_div_passport_jwt_init(stir_shaken_context_t *ss, jwt_t *jwt, stir_shaken_div_passport_params_t *params, unsigned char *key, uint32_t keylen)
{
	ks_json_t *json = NULL;
	ks_json_t *div = NULL;
	char *jstr = NULL;
	stir_shaken_status_t status = STIR_SHAKEN_STATUS_OK;

	if (!jwt || !params) {
		stir_shaken_set_error(ss, "DIV PASSporT: bad params", STIR_SHAKEN_ERROR_BAD_PARAMS_1);
		return STIR_SHAKEN_STATUS_TERM;
	}

	if (stir_shaken_zstr(params->x5u) || stir_shaken_zstr(params->orig_val) || !params->dest_vals || params->dest_vals_count == 0 || stir_shaken_zstr(params->div_val) || !params->iat) {
		stir_shaken_set_error(ss, "DIV PASSporT: required field missing", STIR_SHAKEN_ERROR_BAD_PARAMS_2);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	if (!stir_shaken_header_value_is_safe(params->x5u) || !stir_shaken_header_value_is_safe(params->reason) || !stir_shaken_header_value_is_safe(params->hi)) {
		stir_shaken_set_error(ss, "DIV PASSporT: unsafe header or claim value", STIR_SHAKEN_ERROR_BAD_PARAMS_3);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	if (stir_shaken_validate_identity_key(ss, params->orig_key) != STIR_SHAKEN_STATUS_OK ||
		stir_shaken_validate_identity_key(ss, params->dest_key) != STIR_SHAKEN_STATUS_OK ||
		stir_shaken_validate_identity_key(ss, params->div_key) != STIR_SHAKEN_STATUS_OK) {
		return STIR_SHAKEN_STATUS_FALSE;
	}

	if ((params->flags & STIR_SHAKEN_DIV_FLAG_INCLUDE_SHAKEN_CLAIMS) && stir_shaken_validate_attest(ss, params->attest) != STIR_SHAKEN_STATUS_OK) {
		return STIR_SHAKEN_STATUS_FALSE;
	}

	if (jwt_add_header(jwt, "ppt", STIR_SHAKEN_PPT_DIV) != 0 ||
		jwt_add_header(jwt, "typ", "passport") != 0 ||
		jwt_add_header(jwt, "x5u", params->x5u) != 0) {
		stir_shaken_set_error(ss, "DIV PASSporT: failed to add JOSE headers", STIR_SHAKEN_ERROR_JWT_ADD_HEADERS_JSON);
		return STIR_SHAKEN_STATUS_ERR;
	}

	if (key && keylen && jwt_set_alg(jwt, JWT_ALG_ES256, key, keylen) != 0) {
		stir_shaken_set_error(ss, "DIV PASSporT: failed to set ES256", STIR_SHAKEN_ERROR_JWT_SET_ALG_ES256_1);
		return STIR_SHAKEN_STATUS_ERR;
	}

	json = ks_json_create_object();
	if (!json) {
		stir_shaken_set_error(ss, "DIV PASSporT: failed to create payload JSON", STIR_SHAKEN_ERROR_KSJSON_CREATE_OBJECT_JSON_1);
		return STIR_SHAKEN_STATUS_ERR;
	}

#if KS_VERSION_NUM >= 20000
	ks_json_add_number_to_object(json, "iat", params->iat);
#else
	if (!ks_json_add_number_to_object(json, "iat", params->iat)) {
		stir_shaken_set_error(ss, "DIV PASSporT: failed to add iat", STIR_SHAKEN_ERROR_KSJSON_ADD_IAT);
		status = STIR_SHAKEN_STATUS_ERR;
		goto done;
	}
#endif

	if ((status = stir_shaken_json_add_identity_object(ss, json, "orig", params->orig_key, params->orig_val)) != STIR_SHAKEN_STATUS_OK) goto done;
	if ((status = stir_shaken_json_add_dest_object(ss, json, params->dest_key, params->dest_vals, params->dest_vals_count)) != STIR_SHAKEN_STATUS_OK) goto done;

	div = ks_json_create_object();
	if (!div) {
		stir_shaken_set_error(ss, "DIV PASSporT: failed to create div JSON", STIR_SHAKEN_ERROR_KSJSON_CREATE_OBJECT_JSON_2);
		status = STIR_SHAKEN_STATUS_ERR;
		goto done;
	}

#if KS_VERSION_NUM >= 20000
	ks_json_add_string_to_object(div, stir_shaken_identity_key_or_default(params->div_key), params->div_val);
	if (!stir_shaken_zstr(params->hi)) ks_json_add_string_to_object(div, "hi", params->hi);
	if ((params->flags & STIR_SHAKEN_DIV_FLAG_INCLUDE_REASON) && !stir_shaken_zstr(params->reason)) ks_json_add_string_to_object(div, "reason", params->reason);
	ks_json_add_item_to_object(json, "div", div);
#else
	if (!ks_json_add_string_to_object(div, stir_shaken_identity_key_or_default(params->div_key), params->div_val) ||
		(!stir_shaken_zstr(params->hi) && !ks_json_add_string_to_object(div, "hi", params->hi)) ||
		((params->flags & STIR_SHAKEN_DIV_FLAG_INCLUDE_REASON) && !stir_shaken_zstr(params->reason) && !ks_json_add_string_to_object(div, "reason", params->reason)) ||
		!ks_json_add_item_to_object(json, "div", div)) {
		ks_json_delete(&div);
		stir_shaken_set_error(ss, "DIV PASSporT: failed to add div claim", STIR_SHAKEN_ERROR_KSJSON_ADD_TN);
		status = STIR_SHAKEN_STATUS_ERR;
		goto done;
	}
#endif
	div = NULL;

	if (params->flags & STIR_SHAKEN_DIV_FLAG_INCLUDE_SHAKEN_CLAIMS) {
#if KS_VERSION_NUM >= 20000
		ks_json_add_string_to_object(json, "attest", params->attest);
		if (!stir_shaken_zstr(params->origid)) ks_json_add_string_to_object(json, "origid", params->origid);
#else
		if (!ks_json_add_string_to_object(json, "attest", params->attest) ||
			(!stir_shaken_zstr(params->origid) && !ks_json_add_string_to_object(json, "origid", params->origid))) {
			stir_shaken_set_error(ss, "DIV PASSporT: failed to add compatibility claims", STIR_SHAKEN_ERROR_KSJSON_ADD_ATTEST);
			status = STIR_SHAKEN_STATUS_ERR;
			goto done;
		}
#endif
	}

	jstr = ks_json_print_unformatted(json);
	if (!jstr) {
		stir_shaken_set_error(ss, "DIV PASSporT: failed to print payload JSON", STIR_SHAKEN_ERROR_PASSPORT_JWT_PRINT_JSON);
		status = STIR_SHAKEN_STATUS_TERM;
		goto done;
	}

	if (jwt_add_grants_json(jwt, jstr) != 0) {
		stir_shaken_set_error(ss, "DIV PASSporT: failed to add grants JSON", STIR_SHAKEN_ERROR_PASSPORT_JWT_ADD_GRANTS_JSON);
		status = STIR_SHAKEN_STATUS_TERM;
		goto done;
	}

done:
	if (div) ks_json_delete(&div);
	if (json) ks_json_delete(&json);
	return status;
}

void stir_shaken_div_passport_params_destroy(stir_shaken_div_passport_params_t *params)
{
	uint32_t i = 0;

	if (!params) return;
	free((char *) params->x5u);
	free((char *) params->orig_key);
	free((char *) params->orig_val);
	free((char *) params->dest_key);
	if (params->dest_vals) {
		for (i = 0; i < params->dest_vals_count; i++) free((char *) params->dest_vals[i]);
		free((char **) params->dest_vals);
	}
	free((char *) params->div_key);
	free((char *) params->div_val);
	free((char *) params->hi);
	free((char *) params->reason);
	free((char *) params->attest);
	free((char *) params->origid);
	memset(params, 0, sizeof(*params));
}

stir_shaken_passport_t *stir_shaken_div_passport_create(stir_shaken_context_t *ss, stir_shaken_div_passport_params_t *params, unsigned char *key, uint32_t keylen)
{
	stir_shaken_passport_t *passport = NULL;

	passport = malloc(sizeof(*passport));
	if (!passport) {
		stir_shaken_set_error(ss, "Can't allocate DIV PASSporT", STIR_SHAKEN_ERROR_MEM_PASSPORT);
		return NULL;
	}
	memset(passport, 0, sizeof(*passport));

	passport->jwt = stir_shaken_passport_jwt_create_new(ss);
	if (!passport->jwt) goto fail;

	if (stir_shaken_div_passport_jwt_init(ss, passport->jwt, params, key, keylen) != STIR_SHAKEN_STATUS_OK) goto fail;

	return passport;

fail:
	stir_shaken_passport_destroy(&passport);
	return NULL;
}

stir_shaken_status_t stir_shaken_div_authenticate_keep_passport(stir_shaken_context_t *ss, char **sih, stir_shaken_div_passport_params_t *params, unsigned char *key, uint32_t keylen, stir_shaken_passport_t **passport_out)
{
	stir_shaken_passport_t *passport = NULL;

	if (!sih) {
		stir_shaken_set_error(ss, "DIV authenticate: bad params", STIR_SHAKEN_ERROR_BAD_PARAMS_4);
		return STIR_SHAKEN_STATUS_TERM;
	}

	passport = stir_shaken_div_passport_create(ss, params, key, keylen);
	if (!passport) {
		stir_shaken_set_error(ss, "Failed to create DIV PASSporT", STIR_SHAKEN_ERROR_PASSPORT_CREATE_1);
		return STIR_SHAKEN_STATUS_TERM;
	}

	*sih = stir_shaken_jwt_sip_identity_create(ss, passport, key, keylen);
	if (!*sih) {
		stir_shaken_passport_destroy(&passport);
		stir_shaken_set_error(ss, "Failed to create DIV SIP Identity Header", STIR_SHAKEN_ERROR_SIH_CREATE);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	if (passport_out) {
		*passport_out = passport;
	} else {
		stir_shaken_passport_destroy(&passport);
	}

	return STIR_SHAKEN_STATUS_OK;
}

stir_shaken_status_t stir_shaken_div_authenticate(stir_shaken_context_t *ss, char **sih, stir_shaken_div_passport_params_t *params, unsigned char *key, uint32_t keylen)
{
	return stir_shaken_div_authenticate_keep_passport(ss, sih, params, key, keylen, NULL);
}

stir_shaken_status_t stir_shaken_sih_parse(stir_shaken_context_t *ss, const char *sih, stir_shaken_parsed_identity_t *out)
{
	const char *semi = NULL;
	const char *p = NULL;
	size_t token_len = 0;

	if (!sih || !out || strchr(sih, '\r') || strchr(sih, '\n')) {
		stir_shaken_set_error(ss, "SIP Identity parse: bad params", STIR_SHAKEN_ERROR_BAD_PARAMS_5);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	memset(out, 0, sizeof(*out));
	semi = strchr(sih, ';');
	if (!semi || semi == sih) {
		stir_shaken_set_error(ss, "SIP Identity parse: malformed header", STIR_SHAKEN_ERROR_PASSPORT_MALFORMED);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	token_len = (size_t) (semi - sih);
	out->passport_token = malloc(token_len + 1);
	if (!out->passport_token) {
		stir_shaken_set_error(ss, "Out of memory", STIR_SHAKEN_ERROR_MEM_ID);
		return STIR_SHAKEN_STATUS_TERM;
	}
	memcpy(out->passport_token, sih, token_len);
	out->passport_token[token_len] = '\0';

	p = semi + 1;
	while (*p) {
		const char *eq = strchr(p, '=');
		const char *next = strchr(p, ';');
		size_t key_len = 0;
		size_t val_len = 0;
		const char *val = NULL;
		char **slot = NULL;

		if (!next) next = p + strlen(p);
		if (!eq || eq > next) {
			p = *next ? next + 1 : next;
			continue;
		}

		key_len = (size_t) (eq - p);
		val = eq + 1;
		val_len = (size_t) (next - val);

		if (key_len == 4 && !strncmp(p, "info", key_len)) slot = &out->info;
		else if (key_len == 3 && !strncmp(p, "alg", key_len)) slot = &out->alg;
		else if (key_len == 3 && !strncmp(p, "ppt", key_len)) slot = &out->ppt;

		if (slot && !*slot) {
			if (val_len >= 2 && val[0] == '<' && val[val_len - 1] == '>') {
				val++;
				val_len -= 2;
			}
			*slot = malloc(val_len + 1);
			if (!*slot) {
				stir_shaken_sih_parse_destroy(out);
				stir_shaken_set_error(ss, "Out of memory", STIR_SHAKEN_ERROR_MEM_ID);
				return STIR_SHAKEN_STATUS_TERM;
			}
			memcpy(*slot, val, val_len);
			(*slot)[val_len] = '\0';
		}

		p = *next ? next + 1 : next;
	}

	return STIR_SHAKEN_STATUS_OK;
}

void stir_shaken_sih_parse_destroy(stir_shaken_parsed_identity_t *parsed)
{
	if (!parsed) return;
	free(parsed->passport_token);
	free(parsed->info);
	free(parsed->alg);
	free(parsed->ppt);
	memset(parsed, 0, sizeof(*parsed));
}

stir_shaken_status_t stir_shaken_passport_decode_noverify(stir_shaken_context_t *ss, const char *passport_token, stir_shaken_passport_t **passport_out)
{
	jwt_t *jwt = NULL;
	stir_shaken_passport_t *passport = NULL;

	if (!passport_token || !passport_out) {
		stir_shaken_set_error(ss, "PASSporT decode: bad params", STIR_SHAKEN_ERROR_BAD_PARAMS_6);
		return STIR_SHAKEN_STATUS_TERM;
	}

	if (jwt_decode(&jwt, passport_token, NULL, 0) != 0) {
		stir_shaken_set_error(ss, "PASSporT decode: invalid JWT", STIR_SHAKEN_ERROR_JWT_DECODE_1);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	passport = stir_shaken_passport_create(ss, NULL, NULL, 0);
	if (!passport) {
		jwt_free(jwt);
		return STIR_SHAKEN_STATUS_TERM;
	}

	if (!stir_shaken_jwt_move_to_passport(ss, jwt, passport)) {
		jwt_free(jwt);
		stir_shaken_passport_destroy(&passport);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	*passport_out = passport;
	return STIR_SHAKEN_STATUS_OK;
}

static stir_shaken_status_t stir_shaken_extract_dest_selection(stir_shaken_context_t *ss, ks_json_t *dest, const char *selected_key, const char *selected_val, char **key_out, char **val_out)
{
	const char *keys[] = { "tn", "uri" };
	uint32_t total = 0;
	uint32_t i = 0;
	const char *sole_key = NULL;
	const char *sole_val = NULL;

	for (i = 0; i < 2; i++) {
		ks_json_t *arr = ks_json_get_object_item(dest, keys[i]);
		int size = 0;
		int j = 0;

		if (!arr) continue;
		if (ks_json_type_get(arr) != KS_JSON_TYPE_ARRAY) {
			stir_shaken_set_error(ss, "Original @dest must use array form", STIR_SHAKEN_ERROR_PASSPORT_INVALID_DEST);
			return STIR_SHAKEN_STATUS_FALSE;
		}

		size = ks_json_get_array_size(arr);
		for (j = 0; j < size; j++) {
			ks_json_t *item = ks_json_get_array_item(arr, j);
			const char *value = NULL;

			if (!item || ks_json_type_get(item) != KS_JSON_TYPE_STRING) continue;
#if KS_VERSION_NUM >= 20000
			ks_json_value_string(item, &value);
#else
			value = ks_json_value_string(item);
#endif
			if (!stir_shaken_zstr(value)) {
				total++;
				sole_key = keys[i];
				sole_val = value;
			}

			if (!stir_shaken_zstr(selected_val) && !strcmp(selected_val, value) && (stir_shaken_zstr(selected_key) || !strcmp(selected_key, keys[i]))) {
				*key_out = strdup(keys[i]);
				*val_out = strdup(value);
				if (!*key_out || !*val_out) {
					free(*key_out);
					free(*val_out);
					*key_out = NULL;
					*val_out = NULL;
					stir_shaken_set_error(ss, "Out of memory", STIR_SHAKEN_ERROR_MEM_ID);
					return STIR_SHAKEN_STATUS_TERM;
				}
				return STIR_SHAKEN_STATUS_OK;
			}
		}
	}

	if (stir_shaken_zstr(selected_val) && total == 1) {
		*key_out = strdup(sole_key);
		*val_out = strdup(sole_val);
		if (!*key_out || !*val_out) {
			free(*key_out);
			free(*val_out);
			*key_out = NULL;
			*val_out = NULL;
			stir_shaken_set_error(ss, "Out of memory", STIR_SHAKEN_ERROR_MEM_ID);
			return STIR_SHAKEN_STATUS_TERM;
		}
		return STIR_SHAKEN_STATUS_OK;
	}

	if (stir_shaken_zstr(selected_val) && total > 1) {
		stir_shaken_set_error(ss, "Original @dest has multiple values; selected original destination is required", STIR_SHAKEN_ERROR_BAD_PARAMS_7);
	} else {
		stir_shaken_set_error(ss, "Selected original destination is not present in original @dest", STIR_SHAKEN_ERROR_BAD_PARAMS_8);
	}
	return STIR_SHAKEN_STATUS_FALSE;
}

stir_shaken_status_t stir_shaken_div_params_from_original_sih(stir_shaken_context_t *ss, const char *original_sih, const char *div_x5u, const char *new_dest_key, const char **new_dest_vals, uint32_t new_dest_vals_count, const char *selected_original_dest_key, const char *selected_original_dest_val, uint32_t flags, stir_shaken_div_passport_params_t *out)
{
	stir_shaken_parsed_identity_t parsed = { 0 };
	stir_shaken_passport_t *passport = NULL;
	char *orig_json = NULL;
	char *dest_json = NULL;
	ks_json_t *orig = NULL;
	ks_json_t *dest = NULL;
	uint32_t i = 0;
	stir_shaken_status_t status = STIR_SHAKEN_STATUS_FALSE;

	if (!out || stir_shaken_zstr(div_x5u) || !new_dest_vals || new_dest_vals_count == 0) {
		stir_shaken_set_error(ss, "DIV params from SIH: bad params", STIR_SHAKEN_ERROR_BAD_PARAMS_9);
		return STIR_SHAKEN_STATUS_TERM;
	}

	memset(out, 0, sizeof(*out));
	if (stir_shaken_sih_parse(ss, original_sih, &parsed) != STIR_SHAKEN_STATUS_OK) goto done;
	if (parsed.ppt && strcmp(parsed.ppt, STIR_SHAKEN_PPT_SHAKEN)) {
		stir_shaken_set_error(ss, "Original SIP Identity header is not SHAKEN", STIR_SHAKEN_ERROR_PASSPORT_INVALID_PPT);
		goto done;
	}
	if (stir_shaken_passport_decode_noverify(ss, parsed.passport_token, &passport) != STIR_SHAKEN_STATUS_OK) goto done;

	orig_json = stir_shaken_passport_get_grants_json(ss, passport, "orig");
	dest_json = stir_shaken_passport_get_grants_json(ss, passport, "dest");
	if (!orig_json || !dest_json) {
		stir_shaken_set_error(ss, "Original PASSporT missing @orig or @dest", STIR_SHAKEN_ERROR_PASSPORT_GRANTS_INVALID);
		goto done;
	}

	orig = ks_json_parse(orig_json);
	dest = ks_json_parse(dest_json);
	if (!orig || !dest) {
		stir_shaken_set_error(ss, "Failed to parse original PASSporT claims", STIR_SHAKEN_ERROR_PASSPORT_GRANTS_INVALID);
		goto done;
	}

	out->x5u = strdup(div_x5u);
	out->dest_key = strdup(stir_shaken_identity_key_or_default(new_dest_key));
	out->dest_vals = calloc(new_dest_vals_count, sizeof(*out->dest_vals));
	out->dest_vals_count = new_dest_vals_count;
	out->iat = (uint32_t) stir_shaken_passport_get_grant_int(ss, passport, "iat");
	out->flags = flags;
	if (!out->x5u || !out->dest_key || !out->dest_vals || !out->iat) {
		stir_shaken_set_error(ss, "DIV params from SIH: required value missing", STIR_SHAKEN_ERROR_BAD_PARAMS_10);
		status = STIR_SHAKEN_STATUS_FALSE;
		goto fail_out;
	}

	for (i = 0; i < new_dest_vals_count; i++) {
		if (stir_shaken_zstr(new_dest_vals[i])) {
			stir_shaken_set_error(ss, "DIV params from SIH: new destination missing", STIR_SHAKEN_ERROR_BAD_PARAMS_11);
			status = STIR_SHAKEN_STATUS_FALSE;
			goto fail_out;
		}
		out->dest_vals[i] = strdup(new_dest_vals[i]);
		if (!out->dest_vals[i]) {
			stir_shaken_set_error(ss, "Out of memory", STIR_SHAKEN_ERROR_MEM_ID);
			status = STIR_SHAKEN_STATUS_TERM;
			goto fail_out;
		}
	}

	status = stir_shaken_json_get_identity_dup(ss, orig, (char **) &out->orig_key, (char **) &out->orig_val);
	if (status != STIR_SHAKEN_STATUS_OK) goto fail_out;

	status = stir_shaken_extract_dest_selection(ss, dest, selected_original_dest_key, selected_original_dest_val, (char **) &out->div_key, (char **) &out->div_val);
	if (status != STIR_SHAKEN_STATUS_OK) goto fail_out;

	if (flags & STIR_SHAKEN_DIV_FLAG_INCLUDE_SHAKEN_CLAIMS) {
		const char *attest = stir_shaken_passport_get_grant(ss, passport, "attest");
		const char *origid = stir_shaken_passport_get_grant(ss, passport, "origid");

		if (stir_shaken_validate_attest(ss, attest) != STIR_SHAKEN_STATUS_OK) {
			status = STIR_SHAKEN_STATUS_FALSE;
			goto fail_out;
		}
		out->attest = strdup(attest);
		if (!stir_shaken_zstr(origid)) out->origid = strdup(origid);
		if (!out->attest || (!stir_shaken_zstr(origid) && !out->origid)) {
			stir_shaken_set_error(ss, "Out of memory", STIR_SHAKEN_ERROR_MEM_ID);
			status = STIR_SHAKEN_STATUS_TERM;
			goto fail_out;
		}
	}

	status = STIR_SHAKEN_STATUS_OK;
	goto done;

fail_out:
	stir_shaken_div_passport_params_destroy(out);

done:
	if (orig) ks_json_delete(&orig);
	if (dest) ks_json_delete(&dest);
	if (orig_json) free(orig_json);
	if (dest_json) free(dest_json);
	stir_shaken_passport_destroy(&passport);
	stir_shaken_sih_parse_destroy(&parsed);
	return status;
}

stir_shaken_status_t stir_shaken_div_passport_validate_headers(stir_shaken_context_t *ss, stir_shaken_passport_t *passport)
{
	const char *h = NULL;

	if (!passport) return STIR_SHAKEN_STATUS_TERM;

	h = stir_shaken_passport_get_header(ss, passport, "alg");
	if (!h || strcmp(h, "ES256")) {
		stir_shaken_set_error(ss, "DIV PASSporT Invalid. @alg should be 'ES256'", STIR_SHAKEN_ERROR_PASSPORT_INVALID_ALG);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	h = stir_shaken_passport_get_header(ss, passport, "ppt");
	if (!h || strcmp(h, STIR_SHAKEN_PPT_DIV)) {
		stir_shaken_set_error(ss, "DIV PASSporT Invalid. @ppt should be 'div'", STIR_SHAKEN_ERROR_PASSPORT_INVALID_PPT);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	h = stir_shaken_passport_get_header(ss, passport, "typ");
	if (!h || strcmp(h, "passport")) {
		stir_shaken_set_error(ss, "DIV PASSporT Invalid. @typ should be 'passport'", STIR_SHAKEN_ERROR_PASSPORT_INVALID_TYP);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	h = stir_shaken_passport_get_header(ss, passport, "x5u");
	if (stir_shaken_zstr(h)) {
		stir_shaken_set_error(ss, "DIV PASSporT Invalid. @x5u is missing", STIR_SHAKEN_ERROR_PASSPORT_INVALID_X5U);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	return STIR_SHAKEN_STATUS_OK;
}

stir_shaken_status_t stir_shaken_div_passport_validate_grants(stir_shaken_context_t *ss, stir_shaken_passport_t *passport)
{
	char *orig = NULL;
	char *dest = NULL;
	char *div = NULL;
	char *opt = NULL;
	long int iat = 0;
	stir_shaken_status_t status = STIR_SHAKEN_STATUS_OK;

	if (!passport) return STIR_SHAKEN_STATUS_TERM;

	iat = stir_shaken_passport_get_grant_int(ss, passport, "iat");
	if (errno == ENOENT || iat == 0) {
		stir_shaken_set_error(ss, "DIV PASSporT Invalid. @iat is missing", STIR_SHAKEN_ERROR_PASSPORT_INVALID_IAT);
		status = STIR_SHAKEN_STATUS_FALSE;
		goto done;
	}

	orig = stir_shaken_passport_get_grants_json(ss, passport, "orig");
	dest = stir_shaken_passport_get_grants_json(ss, passport, "dest");
	div = stir_shaken_passport_get_grants_json(ss, passport, "div");
	opt = stir_shaken_passport_get_grants_json(ss, passport, "opt");

	if (stir_shaken_zstr(orig) || stir_shaken_zstr(dest) || stir_shaken_zstr(div)) {
		stir_shaken_set_error(ss, "DIV PASSporT Invalid. required grant missing", STIR_SHAKEN_ERROR_PASSPORT_GRANTS_INVALID);
		status = STIR_SHAKEN_STATUS_FALSE;
		goto done;
	}

	if (!stir_shaken_zstr(opt)) {
		stir_shaken_set_error(ss, "DIV PASSporT Invalid. @opt is not allowed for ppt=div", STIR_SHAKEN_ERROR_PASSPORT_GRANTS_INVALID);
		status = STIR_SHAKEN_STATUS_FALSE;
	}

done:
	if (orig) free(orig);
	if (dest) free(dest);
	if (div) free(div);
	if (opt) free(opt);
	return status;
}

stir_shaken_status_t stir_shaken_div_passport_validate_headers_and_grants(stir_shaken_context_t *ss, stir_shaken_passport_t *passport)
{
	if (stir_shaken_div_passport_validate_headers(ss, passport) != STIR_SHAKEN_STATUS_OK) return STIR_SHAKEN_STATUS_FALSE;
	return stir_shaken_div_passport_validate_grants(ss, passport);
}

stir_shaken_status_t stir_shaken_div_validate_chain_claims(stir_shaken_context_t *ss, stir_shaken_passport_t *original, stir_shaken_passport_t *div)
{
	char *orig_orig = NULL;
	char *div_orig = NULL;
	char *div_claim = NULL;
	stir_shaken_status_t status = STIR_SHAKEN_STATUS_FALSE;

	if (!original || !div) return STIR_SHAKEN_STATUS_TERM;
	if (stir_shaken_div_passport_validate_headers_and_grants(ss, div) != STIR_SHAKEN_STATUS_OK) return STIR_SHAKEN_STATUS_FALSE;

	orig_orig = stir_shaken_passport_get_grants_json(ss, original, "orig");
	div_orig = stir_shaken_passport_get_grants_json(ss, div, "orig");
	div_claim = stir_shaken_passport_get_grants_json(ss, div, "div");
	if (!orig_orig || !div_orig || !div_claim || strcmp(orig_orig, div_orig)) {
		stir_shaken_set_error(ss, "DIV chain Invalid. @orig mismatch", STIR_SHAKEN_ERROR_PASSPORT_INVALID_ORIG);
		goto done;
	}

	status = STIR_SHAKEN_STATUS_OK;

done:
	if (orig_orig) free(orig_orig);
	if (div_orig) free(div_orig);
	if (div_claim) free(div_claim);
	return status;
}
