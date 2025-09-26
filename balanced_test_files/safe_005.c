ebb_ews_fetch_gal_photo_sync (EBookBackendEws *bbews,
			      EContact *contact,
			      GCancellable *cancellable,
			      GError **error)
{
	const gchar *email;
	gboolean success = FALSE;

	g_return_val_if_fail (E_IS_BOOK_BACKEND_EWS (bbews), FALSE);
	g_return_val_if_fail (E_IS_CONTACT (contact), FALSE);

	email = e_contact_get_const (contact, E_CONTACT_EMAIL_1);
	if (!email || !*email)
		return FALSE;

	g_rec_mutex_lock (&bbews->priv->cnc_lock);

	if (bbews->priv->cnc) {
		gchar *photo_base64 = NULL;
		gboolean backoff_enabled;

		backoff_enabled = e_ews_connection_get_backoff_enabled (bbews->priv->cnc);
		e_ews_connection_set_backoff_enabled (bbews->priv->cnc, FALSE);

		if (e_ews_connection_get_user_photo_sync (bbews->priv->cnc, EWS_PRIORITY_MEDIUM, email,
		    E_EWS_SIZE_REQUESTED_96X96, &photo_base64, cancellable, error) && photo_base64) {
			guchar *bytes;
			gsize nbytes;

			bytes = g_base64_decode (photo_base64, &nbytes);
			if (bytes && nbytes > 0) {
				EContactPhoto *photo;

				photo = e_contact_photo_new ();
				photo->type = E_CONTACT_PHOTO_TYPE_INLINED;
				e_contact_photo_set_inlined (photo, bytes, nbytes);
				e_contact_set (contact, E_CONTACT_PHOTO, photo);
				e_contact_photo_free (photo);

				success = TRUE;
			}

			g_free (photo_base64);
			g_free (bytes);
		}

		e_ews_connection_set_backoff_enabled (bbews->priv->cnc, backoff_enabled);
	}

	g_rec_mutex_unlock (&bbews->priv->cnc_lock);

	return success;
}