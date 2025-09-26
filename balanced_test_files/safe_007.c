void FAST_FUNC udhcp_add_binary_option(struct dhcp_packet *packet, uint8_t *addopt)
{
	unsigned len;
	uint8_t *optionptr = packet->options;
	unsigned end = udhcp_end_option(optionptr);

	len = OPT_DATA + addopt[OPT_LEN];
	/* end position + (option code/length + addopt length) + end option */
	if (end + len + 1 >= DHCP_OPTIONS_BUFSIZE) {
//TODO: learn how to use overflow option if we exhaust packet->options[]
		bb_error_msg("option 0x%02x did not fit into the packet",
				addopt[OPT_CODE]);
		return;
	}
	log_option("Adding option", addopt);
	memcpy(optionptr + end, addopt, len);
	optionptr[end + len] = DHCP_END;
}