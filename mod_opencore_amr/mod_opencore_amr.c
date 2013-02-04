/* 
 * AMR codec module for FreeSWITCH based on opencore-amr library
 * Copyright (C) 2013 Yuriy Ostapchuk
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * Contains portions of code from FreeSWITCH Modular Media Switching Software Library
 * copyright Anthony Minessale II and other contributors
 *
 * Contains portions of code from The Android Open Source Project
 * licensed under the Apache License, Version 2.0
 *
 */
 
/*
 * Patent Disclaimer:
 *
 * AMR and GSM-EFR codecs are covered by patents in the US and some other countries. 
 * Usage of the software that implements these codecs may require patent licenses 
 * from the relevant patent holders.
 *
 * This module does not implement any patented codec algorithms. It's just an interface
 * to the external dynamically linked library that performs actual encoding and decoding.
 * The author is not responsible for any illegal usage of this source code.
 *
 */

#include <switch.h>

#include "opencore-amrnb/interf_enc.h"
#include "opencore-amrnb/interf_dec.h"

SWITCH_MODULE_LOAD_FUNCTION(mod_opencore_load);
SWITCH_MODULE_DEFINITION(mod_opencore_amr, mod_opencore_load, NULL, NULL);

typedef struct amr_codex_config {
	int mode;
	int request_mode;
	int modeset;
	int dtx;
	int octet_align;
	char fmtp[64];
} amr_codec_config_t;


typedef struct amr_ctx {
	void* dec_ctx;
	void* enc_ctx;
	amr_codec_config_t cfg;
} amr_ctx_t;

static amr_codec_config_t amr_default_config = {
	7,
	15,
	0xFF,
	0,
	0,
	""
};

enum Frame_Type_3GPP
{
	AMR_475 = 0,        /* 4.75 kbps    */
	AMR_515,            /* 5.15 kbps    */
	AMR_59,             /* 5.9 kbps     */
	AMR_67,             /* 6.7 kbps     */
	AMR_74,             /* 7.4 kbps     */
	AMR_795,            /* 7.95 kbps    */
	AMR_102,            /* 10.2 kbps    */
	AMR_122,            /* 12.2 kbps    */
	AMR_SID,            /* GSM AMR DTX  */
	GSM_EFR_SID,        /* GSM EFR DTX  */
	TDMA_EFR_SID,       /* TDMA EFR DTX */
	PDC_EFR_SID,        /* PDC EFR DTX  */
	FOR_FUTURE_USE1,    /* Unused 1     */
	FOR_FUTURE_USE2,    /* Unused 2     */
	FOR_FUTURE_USE3,    /* Unused 3     */
	AMR_NO_DATA			/* No data      */
};      

const int gFrameBits[16] = {95, 103, 118, 134, 148, 159, 204, 244, 39, 0, 0, 0, 0, 0, 0, 0};

#define AMR_BITRATE_DUMMY 0
const int amr_bitrates[9] = {4750, 5150, 5900, 6700, 7400, 7950, 10200, 12200, AMR_BITRATE_DUMMY};

static int mod_opencore_parse_mode_string(char* fmtp)
{
	char* modes = fmtp ? strcasestr(fmtp, "mode-set=") : NULL;
	int modeset = 0;
	if (modes) {
		for (char c = *modes; c && c != ' '; c = *++modes) {
			if (c >= '0' && c <= '7') {
				modeset |= 1 << (c - '0');
			}
		}
	}
	return (modeset == 0 ? 0xFF : modeset);
} 

static void mod_opencore_make_mode_string(int modeset, char* modes)
{
	if ((modeset & 0xFF) == 0 /*|| (modeset & 0xFF) == 0xFF*/) {
		modes[0] = 0;
		return;
	}
	strcpy(modes, "mode-set=");
	for (char m = 0; m <= 7; m++) {
		int l;
		if (modeset & (1 << m)) {
			l = strlen(modes);
			if (l > 9) 
				modes[l++] = ',';
			modes[l++] = m + '0';
			modes[l] = '\0';
		}
	}
} 



static switch_status_t mod_opencore_init(switch_codec_t *codec, switch_codec_flag_t flags, const switch_codec_settings_t *codec_settings)
{
	amr_ctx_t* ctx = NULL;
	uint32_t enc, dec;
	char modes[32]; 
	int modeset_in; 

	enc = (flags & SWITCH_CODEC_FLAG_ENCODE);
	dec = (flags & SWITCH_CODEC_FLAG_DECODE);
	
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "mod_opencore_init: dec=%d, enc=%d, codec=%s, fmtp_in=%s, impl_fmtp=%s, bps=%d\n",
						(dec!=0), (enc!=0), codec->codec_interface->interface_name, codec->fmtp_in, codec->implementation->fmtp, 
						codec->implementation->bits_per_second);	
	
	if (!enc && !dec)
		return SWITCH_STATUS_FALSE;

	if (!(ctx = (amr_ctx_t*)switch_core_alloc(codec->memory_pool, sizeof(*ctx))))
		return SWITCH_STATUS_FALSE;
	memset(ctx, 0, sizeof(*ctx));
	codec->private_info = ctx;
	
	if (strcmp(codec->codec_interface->interface_name, "AMR") == 0) {
	
		memcpy(&ctx->cfg, &amr_default_config, sizeof(amr_codec_config_t));
		
		if (codec->implementation->bits_per_second != AMR_BITRATE_DUMMY) {
			for (int n = 0; n <= 7; n++) {
				if (amr_bitrates[n] == codec->implementation->bits_per_second) {
					ctx->cfg.mode = ctx->cfg.request_mode = n;
					break;
				}
			}
		}

		if(codec->fmtp_in) {
			// These parameters are not supported.
			if (strcasestr(codec->fmtp_in, "crc=1") || strcasestr(codec->fmtp_in, "robust-sorting=1") || 
				strcasestr(codec->fmtp_in, "interleaving=")) {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "unsupported fmtp received: %s\n", codec->fmtp_in);
				return SWITCH_STATUS_FALSE;
			}
			
			// Handle mode-set and octet-align.
			modeset_in = mod_opencore_parse_mode_string(codec->fmtp_in);
			ctx->cfg.modeset &= modeset_in;
			if (ctx->cfg.modeset == 0) {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "incompatible AMR mode-sets: %08X vs %08X\n", ctx->cfg.modeset, modeset_in);
				return SWITCH_STATUS_FALSE;
			}
			
			ctx->cfg.octet_align = (strcasestr(codec->fmtp_in, "octet-align=1") != NULL);			
		}
		
		mod_opencore_make_mode_string(ctx->cfg.modeset, modes);
		codec->fmtp_out = switch_core_sprintf(codec->memory_pool, "%s%s", modes, ctx->cfg.octet_align == 1 ? "; octet-align=1" : "");
		
		if (!(ctx->cfg.modeset & (1 << ctx->cfg.mode))) {
			for (char m = 7; m >= 0; m--) {
				if (ctx->cfg.modeset & (1 << m)) {
					ctx->cfg.mode = m;
					break;
				}
			}
		}
		if (!(ctx->cfg.modeset & (1 << ctx->cfg.request_mode)))
			ctx->cfg.request_mode = 15;
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "selecting AMR mode %d, %s\n", ctx->cfg.mode, modes);
	}
	
	
	if (enc) {
		if (!(ctx->enc_ctx = Encoder_Interface_init(ctx->cfg.dtx))) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Encoder_Interface_init error\n");
			return SWITCH_STATUS_FALSE;
		}
	}
	if (dec) {
		if (!(ctx->dec_ctx = Decoder_Interface_init())) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Decoder_Interface_init error\n");
			return SWITCH_STATUS_FALSE;
		}
	}
	
	
	return SWITCH_STATUS_SUCCESS;
}



static switch_status_t mod_opencore_amr_encode(switch_codec_t *codec, switch_codec_t *other_codec,	
										  void *decoded_data,	
										  uint32_t decoded_data_len,
										  uint32_t decoded_rate,
										  void *encoded_data,
										  uint32_t *encoded_data_len,
										  uint32_t *encoded_rate,
										  unsigned int *flag)
{
	amr_ctx_t* ctx = (amr_ctx_t*)codec->private_info;
	
	unsigned char *bytes = (unsigned char *)encoded_data;
    enum Frame_Type_3GPP type;
	int length;
	
	if (!ctx)
		return SWITCH_STATUS_FALSE;
	
	length = Encoder_Interface_Encode(ctx->enc_ctx, (enum Mode)ctx->cfg.mode, (int16_t*)decoded_data, bytes + 1, 0);
	type = (enum Frame_Type_3GPP)((bytes[1] >> 3) & 0x0F);
	
	if (type == AMR_NO_DATA) {
		//switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "AMR encode: AMR_NO_DATA\n");
		*encoded_data_len = 0;
		return SWITCH_STATUS_SUCCESS;
	}
		
    if ((type != ctx->cfg.mode && type != AMR_SID) || length != (8 + gFrameBits[type] + 7) >> 3) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "AMR encode error: mode %d, type %d, length %d, bytes: %02X %02X %02X %02X %02X\n",
			ctx->cfg.mode, type, length, bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]);	
		return SWITCH_STATUS_FALSE;
    }	

    
	if (ctx->cfg.octet_align) {
        bytes[0] = ctx->cfg.request_mode << 4;
		bytes[1] = (type << 3) | 0x04;
        ++length;
    } else {

        // Shift left 6 bits and update the length.
        bytes[1] = 0;
		bytes[length + 1] = 0;
        for (int i = 1; i <= length; ++i) {
            bytes[i] = (bytes[i] << 6) | (bytes[i + 1] >> 2);
        }
		
		// CMR = 15 (4-bit), F = 0 (1-bit), FT = mMode (4-bit), Q = 1 (1-bit).
		bytes[0] = ctx->cfg.request_mode << 4 | type >> 1;
		bytes[1] = bytes[1] | type << 7 | 0x40;
		
        length = (10 + gFrameBits[type] + 7) >> 3;
    }
    *encoded_data_len = length;
	return SWITCH_STATUS_SUCCESS;
}



static switch_status_t mod_opencore_amr_decode(switch_codec_t *codec,
										  switch_codec_t *other_codec,
										  void *encoded_data,
										  uint32_t encoded_data_len,
										  uint32_t encoded_rate,
										  void *decoded_data,
										  uint32_t *decoded_data_len,
										  uint32_t *decoded_rate,
										  unsigned int *flag)
{
	amr_ctx_t* ctx = (amr_ctx_t*)codec->private_info;
	
	unsigned char* bytes = (unsigned char*) encoded_data;
	int length = encoded_data_len;
    
	enum Frame_Type_3GPP type;
	int request;
	
	if (!ctx)
		return SWITCH_STATUS_FALSE;

	*decoded_data_len = 0;		
		
	if (length < 2) {
		//switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "decode error: length < 2\n");	
        return SWITCH_STATUS_SUCCESS;
    }
	
	request = bytes[0] >> 4;

    if (ctx->cfg.octet_align) {
        if ((bytes[1] & 0x84) != 0x04) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "decode error: bad frame type\n");	
            return SWITCH_STATUS_SUCCESS;
        }
        type = (enum Frame_Type_3GPP)(bytes[1] >> 3);
        if (length != (16 + gFrameBits[type] + 7) >> 3) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "decode error: bad length %d\n", length);
            return SWITCH_STATUS_SUCCESS;
        }
        bytes ++;
    } else {
        if ((bytes[0] & 0x08) || !(bytes[1] & 0x40)) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "decode error: bad frame header: %02X %02X, l=%d\n", bytes[0], bytes[1],encoded_data_len);	
            return SWITCH_STATUS_SUCCESS;
        }
        type = (enum Frame_Type_3GPP)((bytes[0] << 1 | bytes[1] >> 7) & 0x0F);
        if (length != (10 + gFrameBits[type] + 7) >> 3) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "decode error: bad length %d\n", length);	
            return SWITCH_STATUS_SUCCESS;
        }

        --length;
        for (int i = 1; i < length; ++i) {
            bytes[i] = (bytes[i] << 2) | (bytes[i + 1] >> 6);
        }
        bytes[length] <<= 2;
        bytes[0] = (type << 3) | 0x04;
    }


	Decoder_Interface_Decode(ctx->dec_ctx,  bytes, (int16_t*)decoded_data, 0);

    // Handle CMR
    if (request < 8 && request != ctx->cfg.mode) {
        for (int i = request; i >= 0; --i) {
            if (ctx->cfg.modeset & (1 << i)) {
                ctx->cfg.mode = request;
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "changing AMR mode to %d\n", ctx->cfg.mode);
                break;
            }
        }
    }
	
	*decoded_data_len = 320;
	return SWITCH_STATUS_SUCCESS;
}






static switch_status_t mod_opencore_efr_encode(switch_codec_t *codec, switch_codec_t *other_codec,	
										  void *decoded_data,	
										  uint32_t decoded_data_len,
										  uint32_t decoded_rate,
										  void *encoded_data,
										  uint32_t *encoded_data_len,
										  uint32_t *encoded_rate,
										  unsigned int *flag)
{
	amr_ctx_t* ctx = (amr_ctx_t*)codec->private_info;
	
	unsigned char *bytes = (unsigned char *)encoded_data;
    enum Frame_Type_3GPP type;
	int length;
	
	if (!ctx)
		return SWITCH_STATUS_FALSE;	
	
	length = Encoder_Interface_Encode(ctx->enc_ctx, MR122, (int16_t*)decoded_data, bytes, 0);
	type = (enum Frame_Type_3GPP)((bytes[0] >> 3) & 0x0F);
	
    if (type != AMR_122 || length != 32)  {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "EFR encode error: type=%d, length=%d\n", type, length);
		return SWITCH_STATUS_FALSE;
    }
        
	bytes[0] = 0xC0 | (bytes[1] >> 4);
	for (int i = 1; i < 31; ++i) {
		bytes[i] = (bytes[i] << 4) | (bytes[i + 1] >> 4);
	}
    
    *encoded_data_len = 31;
	return SWITCH_STATUS_SUCCESS;
}



static switch_status_t mod_opencore_efr_decode(switch_codec_t *codec,
										  switch_codec_t *other_codec,
										  void *encoded_data,
										  uint32_t encoded_data_len,
										  uint32_t encoded_rate,
										  void *decoded_data,
										  uint32_t *decoded_data_len,
										  uint32_t *decoded_rate,
										  unsigned int *flag)
{
	amr_ctx_t* ctx = (amr_ctx_t*)codec->private_info;
	unsigned char* bytes = (unsigned char*) encoded_data;
	unsigned char bytes_al[32];
	
	if (!ctx)
		return SWITCH_STATUS_FALSE;	
		
	if (encoded_data_len != 31) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "EFR decode error: encoded_data_len!=31 (%d)\n", encoded_data_len);
		*decoded_data_len = 0;
		return SWITCH_STATUS_SUCCESS;
	}
	
	for (int i = 31; i >= 1; --i) {
		bytes_al[i] = (bytes[i] >> 4) | (bytes[i - 1] << 4);
	}
	bytes_al[0] = AMR_122 << 3;

	Decoder_Interface_Decode(ctx->dec_ctx, bytes_al, (int16_t*)decoded_data, 0);	
	*decoded_data_len = 320;
	return SWITCH_STATUS_SUCCESS;
}




static switch_status_t mod_opencore_destroy(switch_codec_t *codec)
{
	amr_ctx_t* ctx = (amr_ctx_t*)codec->private_info;
	if (ctx->enc_ctx) 
		Encoder_Interface_exit(ctx->enc_ctx);
	
	if (ctx->dec_ctx) 
		Decoder_Interface_exit(ctx->dec_ctx);
	
	return SWITCH_STATUS_SUCCESS;
}


static void mod_opencore_load_config()
{
	switch_xml_t xml = NULL, x_lists = NULL, x_list = NULL, cfg = NULL;
	char modes[32];
	
	if ((xml = switch_xml_open_cfg("mod_opencore_amr.conf", &cfg, NULL))) {
		if ((x_lists = switch_xml_child(cfg, "settings"))) {
			for (x_list = switch_xml_child(x_lists, "param"); x_list; x_list = x_list->next) {
				const char *name = switch_xml_attr(x_list, "name"); // This needs to be const 
				const char *value = switch_xml_attr(x_list, "value");

				if (switch_strlen_zero(name) || switch_strlen_zero(value))
					continue;     

				if (!strcmp(name, "mode-set")) {
					strcpy(modes,"mode-set=");
					strncat(modes, value, 16); 
					amr_default_config.modeset = mod_opencore_parse_mode_string(modes);
				} else if (!strcmp(name, "default-mode")) {
					int tmp = atoi(value);
					if (switch_is_number(value) && tmp >= 0 && tmp <= 7) {
						amr_default_config.mode = tmp;
					} else {
						switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "ignoring invalid mode value: %s\n", value);
					}
				} else if (!strcmp(name, "default-request-mode")) {
					int tmp = atoi(value);
					if (switch_is_number(value) && tmp >= 0 && tmp <= 7) {
						amr_default_config.request_mode = tmp;
					} else {
						switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "ignoring invalid request-mode value: %s\n", value);
					}
				} else if (!strcasecmp("octet-align", name)) {
					amr_default_config.octet_align = switch_true(value);
				} else if (!strcasecmp("dtx", name)) {
					amr_default_config.dtx = switch_true(value);
				} else {
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Unknown attribute %s\n", name);
				}
			}
		}
	}
	
	mod_opencore_make_mode_string(amr_default_config.modeset, modes);
	snprintf(amr_default_config.fmtp, sizeof(amr_default_config.fmtp), "%s%s", modes, 
			 amr_default_config.octet_align == 1 ? "; octet-align=1" : "");	
}

SWITCH_MODULE_LOAD_FUNCTION(mod_opencore_load)
{
	switch_codec_interface_t *codec_interface;
	*module_interface = switch_loadable_module_create_module_interface(pool, modname);

	mod_opencore_load_config();	
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "AMR default mode=%d, request_mode=%d, dtx=%d, fmtp=\"%s\"\n", 
						amr_default_config.mode, amr_default_config.request_mode, amr_default_config.dtx, amr_default_config.fmtp);
	
	
	
	SWITCH_ADD_CODEC(codec_interface, "AMR");
	for (int n = 0; n <= 8; n++)
	{
		//add implementations for all available modes and default implementation (bitrate=0) as last
		if (n == 8 || amr_default_config.modeset & (1 << n))
			switch_core_codec_add_implementation(pool, codec_interface, SWITCH_CODEC_TYPE_AUDIO,
																 98,	
																 "AMR",
																 amr_default_config.fmtp,
																 8000,
																 8000,
																 amr_bitrates[n],
																 20000,
																 160,
																 320,
																 0,
																 1,
																 1,
																 mod_opencore_init,
																 mod_opencore_amr_encode,
																 mod_opencore_amr_decode,
																 mod_opencore_destroy);
	}															 
	SWITCH_ADD_CODEC(codec_interface, "GSM-EFR");
	switch_core_codec_add_implementation(pool, codec_interface, SWITCH_CODEC_TYPE_AUDIO,
																 99,	
																 "GSM-EFR",
																 NULL,
																 8000,
																 8000,
																 12200,
																 20000,
																 160,
																 320,
																 31,
																 1,
																 1,
																 mod_opencore_init,
																 mod_opencore_efr_encode,
																 mod_opencore_efr_decode,
																 mod_opencore_destroy);																 

	return SWITCH_STATUS_SUCCESS;
}