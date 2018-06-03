/**
 * masq_bytes - masq data on each byte
 * @data: data to be masqed
 * @len: bytes of data
 * @passwd: password
 * returns the recalculated csum
 *
 * You can modify it to custom your own masq method.
 * Masq should be based on each byte, so you can demasq it without any position
 * info later.
 */
static inline __be32 masq_bytes(void *data, int len, unsigned int passwd)
{
	int i;
	__u8 *b;

	b = (__u8 *)data;
	for (i = 0; i < len; i++) {
		*b = ~*b + passwd;
		b++;
	}

    return 0;
}

/**
 * demasq_bytes - demasq data on each byte
 * @data: data to be demasqed
 * @len: bytes of data
 * @passwd: password
 * returns the recalculated csum
 *
 * Corresponding to masq_bytes().
 * Masq is based on each byte, so you can demasq it without any position info
 * now.
 */
static inline __be32 demasq_bytes(void *data, int len, unsigned int passwd)
{
	int i;
	__u8 *b;

	b = (__u8 *)data;
	for (i = 0; i < len; i++) {
		*b = ~(*b - passwd);
		b++;
	}

    return 0;
}
