void SSL_CTX_sess_set_get_cb(SSL_CTX *ctx,
                             SSL_SESSION *(*cb) (struct ssl_st *ssl,
                                                 unsigned char *data, int len,
                                                 int *copy))
{
    ctx->get_session_cb = cb;
}