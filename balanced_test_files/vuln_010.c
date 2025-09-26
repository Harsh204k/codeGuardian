static GF_Err ttml_embed_data(GF_XMLNode *node, u8 *aux_data, u32 aux_data_size, u8 *subs_data, u32 subs_data_size)
{
	u32 i=0;
	GF_XMLNode *child;
	u32 subs_idx=0;
	GF_XMLAttribute *att;
	Bool is_source = GF_FALSE;
	Bool has_src_att = GF_FALSE;
	if (!node || node->type) return GF_BAD_PARAM;

	if (!strcmp(node->name, "source")) {
		is_source = GF_TRUE;
	}

	while ((att = gf_list_enum(node->attributes, &i))) {
		char *sep, *fext;
		if (strcmp(att->name, "src")) continue;
		has_src_att = GF_TRUE;
		if (strncmp(att->value, "urn:", 4)) continue;
		sep = strrchr(att->value, ':');
		if (!sep) continue;
		sep++;
		fext = gf_file_ext_start(sep);
		if (fext) fext[0] = 0;
		subs_idx = atoi(sep);
		if (fext) fext[0] = '.';
		if (!subs_idx || ((subs_idx-1) * 14 > subs_data_size)) {
			subs_idx = 0;
			continue;
		}
		break;
	}
	if (subs_idx) {
		GF_XMLNode *data;
		u32 subs_offset = 0;
		u32 subs_size = 0;
		u32 idx = 1;
		//fetch subsample info
		for (i=0; i<subs_data_size; i+=14) {
			u32 a_subs_size = subs_data[i+4];
			a_subs_size <<= 8;
			a_subs_size |= subs_data[i+5];
			a_subs_size <<= 8;
			a_subs_size |= subs_data[i+6];
			a_subs_size <<= 8;
			a_subs_size |= subs_data[i+7];
			if (idx==subs_idx) {
				subs_size = a_subs_size;
				break;
			}
			subs_offset += a_subs_size;
			idx++;
		}
		if (!subs_size || (subs_offset + subs_size > aux_data_size)) {
			if (!subs_size) {
				GF_LOG(GF_LOG_ERROR, GF_LOG_MEDIA, ("No subsample with index %u in sample\n", subs_idx));
			} else {
				GF_LOG(GF_LOG_ERROR, GF_LOG_MEDIA, ("Corrupted subsample %u info, size %u offset %u but sample size %u\n", subs_idx, subs_size, subs_offset, aux_data_size));
			}
			return GF_NON_COMPLIANT_BITSTREAM;
		}

		//remove src attribute
		gf_list_del_item(node->attributes, att);
		if (att->name) gf_free(att->name);
		if (att->value) gf_free(att->value);
		gf_free(att);

		//create a source node
		if (!is_source) {
			GF_XMLNode *s;
			GF_SAFEALLOC(s, GF_XMLNode);
			if (!s) return GF_OUT_OF_MEM;
			s->attributes = gf_list_new();
			s->content = gf_list_new();
			s->name = gf_strdup("source");
			gf_list_add(node->content, s);
			if (!s->name || !s->content || !s->attributes) return GF_OUT_OF_MEM;
			//move @type to source
			att = ttml_get_attr(node, "type");
			if (att) {
				gf_list_del_item(node->attributes, att);
				gf_list_add(s->attributes, att);
			}
			node = s;
		}

		//create a data node
		GF_SAFEALLOC(data, GF_XMLNode);
		if (!data) return GF_OUT_OF_MEM;
		data->attributes = gf_list_new();
		data->content = gf_list_new();
		data->name = gf_strdup("data");
		gf_list_add(node->content, data);
		if (!data->name || !data->content || !data->attributes) return GF_OUT_OF_MEM;
		//move @type to data
		att = ttml_get_attr(node, "type");
		if (att) {
			gf_list_del_item(node->attributes, att);
			gf_list_add(data->attributes, att);
		}
		//base64 encode in a child
		GF_SAFEALLOC(node, GF_XMLNode)
		if (!node) return GF_OUT_OF_MEM;
		node->type = GF_XML_TEXT_TYPE;
		node->name = gf_malloc(sizeof(u8) * subs_size * 2);
		if (!node->name) {
			gf_free(node);
			return GF_OUT_OF_MEM;
		}
		subs_size = gf_base64_encode(aux_data + subs_offset, subs_size, (u8*) node->name, subs_size * 2);
		node->name[subs_size] = 0;
		return gf_list_add(data->content, node);
	}
	//src was present but not an embedded data, do not recurse
	if (has_src_att) return GF_OK;

	i=0;
	while ((child = gf_list_enum(node->content, &i))) {
		if (child->type) continue;
		ttml_embed_data(child, aux_data, aux_data_size, subs_data, subs_data_size);
	}
	return GF_OK;
}