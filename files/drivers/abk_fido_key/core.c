// SPDX-License-Identifier: GPL-2.0

#include <linux/abk_fido_key.h>

#if IS_ENABLED(CONFIG_ABK_CONTROL)
#include <linux/abk_control.h>
#endif

#include <linux/crc32.h>
#include <linux/err.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/hid.h>
#include <linux/kernel.h>
#include <linux/kmod.h>
#include <linux/kobject.h>
#include <linux/list.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mount.h>
#include <linux/mutex.h>
#include <linux/crypto.h>
#include <linux/cred.h>
#include <linux/idr.h>
#include <linux/namei.h>
#include <linux/poll.h>
#include <linux/random.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/usb/ch9.h>
#include <linux/usb/composite.h>
#include <linux/usb/g_hid.h>
#include <linux/wait.h>
#include <linux/workqueue.h>
#include <linux/jiffies.h>

#include <asm/unaligned.h>

#include <crypto/ecdh.h>
#include <crypto/ecc_curve.h>
#include <crypto/hash.h>
#include <crypto/internal/ecc.h>
#include <crypto/sha2.h>
#include <crypto/skcipher.h>

#include "../usb/gadget/u_f.h"

#define ABK_FIDO_REPORT_LEN			64
#define ABK_FIDO_REPORT_DESC_LEN		34
#define ABK_FIDO_MAX_MSG			2048
#define ABK_FIDO_MAX_CHANNELS			4
#define ABK_FIDO_QUEUE_DEPTH			32
#define ABK_FIDO_MAX_RP_ID			128
#define ABK_FIDO_MAX_USER_ID			64
#define ABK_FIDO_MAX_USER_NAME			64
#define ABK_FIDO_MAX_CREDS			32
#define ABK_FIDO_MAX_CBOR			1536
#define ABK_FIDO_MAX_SIG_DER			80
#define ABK_FIDO_AUTH_CACHE_MS			10000
#define ABK_FIDO_STORE_PATH			"/metadata/abk_fido_store.bin"
#define ABK_FIDO_STORE_MAGIC			0x41424646
#define ABK_FIDO_STORE_VERSION			1
#define ABK_FIDO_PIN_RETRIES_DEFAULT		8
#define ABK_FIDO_PERSIST_ENABLED \
	(IS_ENABLED(CONFIG_ABK_FIDO_KEY_PERSIST_METADATA) || \
	 IS_ENABLED(CONFIG_ABK_FIDO_KEY_PERSIST_ADB_DATA))

#define ABK_FIDO_CID_BROADCAST			0xffffffffU

#define ABK_FIDO_HID_PING			0x01
#define ABK_FIDO_HID_MSG			0x03
#define ABK_FIDO_HID_LOCK			0x04
#define ABK_FIDO_HID_INIT			0x06
#define ABK_FIDO_HID_WINK			0x08
#define ABK_FIDO_HID_CBOR			0x10
#define ABK_FIDO_HID_CANCEL			0x11
#define ABK_FIDO_HID_ERROR			0x3f

#define ABK_FIDO_HID_ERR_INVALID_CMD		0x01
#define ABK_FIDO_HID_ERR_INVALID_PAR		0x02
#define ABK_FIDO_HID_ERR_INVALID_LEN		0x03
#define ABK_FIDO_HID_ERR_INVALID_SEQ		0x04
#define ABK_FIDO_HID_ERR_MSG_TIMEOUT		0x05
#define ABK_FIDO_HID_ERR_CHANNEL_BUSY		0x06
#define ABK_FIDO_HID_ERR_LOCK_REQUIRED		0x0a
#define ABK_FIDO_HID_ERR_INVALID_CID		0x0b
#define ABK_FIDO_HID_ERR_OTHER			0x7f

#define ABK_FIDO_CTAP_SUCCESS			0x00
#define ABK_FIDO_CTAP_ERR_INVALID_COMMAND	0x01
#define ABK_FIDO_CTAP_ERR_INVALID_PARAMETER	0x02
#define ABK_FIDO_CTAP_ERR_INVALID_LENGTH	0x03
#define ABK_FIDO_CTAP_ERR_INVALID_SEQ		0x04
#define ABK_FIDO_CTAP_ERR_TIMEOUT		0x05
#define ABK_FIDO_CTAP_ERR_CBOR_UNEXPECTED_TYPE	0x11
#define ABK_FIDO_CTAP_ERR_INVALID_CBOR		0x12
#define ABK_FIDO_CTAP_ERR_MISSING_PARAMETER	0x14
#define ABK_FIDO_CTAP_ERR_LIMIT_EXCEEDED	0x15
#define ABK_FIDO_CTAP_ERR_CREDENTIAL_EXCLUDED	0x19
#define ABK_FIDO_CTAP_ERR_UNSUPPORTED_ALGORITHM	0x26
#define ABK_FIDO_CTAP_ERR_OPERATION_DENIED	0x27
#define ABK_FIDO_CTAP_ERR_KEY_STORE_FULL	0x28
#define ABK_FIDO_CTAP_ERR_UNSUPPORTED_OPTION	0x2b
#define ABK_FIDO_CTAP_ERR_NO_CREDENTIALS	0x2e
#define ABK_FIDO_CTAP_ERR_PIN_INVALID		0x31
#define ABK_FIDO_CTAP_ERR_PIN_BLOCKED		0x32
#define ABK_FIDO_CTAP_ERR_PIN_AUTH_INVALID	0x33
#define ABK_FIDO_CTAP_ERR_PIN_NOT_SET		0x35

#define ABK_FIDO_CTAP_MAKE_CREDENTIAL		0x01
#define ABK_FIDO_CTAP_GET_ASSERTION		0x02
#define ABK_FIDO_CTAP_GET_INFO			0x04
#define ABK_FIDO_CTAP_CLIENT_PIN		0x06
#define ABK_FIDO_CTAP_RESET			0x07
#define ABK_FIDO_CTAP_SELECTION		0x0b

#define ABK_FIDO_CLIENT_PIN_GET_RETRIES		0x01
#define ABK_FIDO_CLIENT_PIN_GET_KEY_AGREEMENT	0x02
#define ABK_FIDO_CLIENT_PIN_SET_PIN		0x03
#define ABK_FIDO_CLIENT_PIN_CHANGE_PIN		0x04
#define ABK_FIDO_CLIENT_PIN_GET_PIN_TOKEN	0x05

#define ABK_FIDO_COSE_KTY_EC2			2
#define ABK_FIDO_COSE_ALG_ES256			(-7)
#define ABK_FIDO_COSE_ALG_ECDH_ES_HKDF_256	(-25)
#define ABK_FIDO_COSE_CRV_P256			1

#define ABK_FIDO_CRED_FLAG_UP			0x01
#define ABK_FIDO_CRED_FLAG_UV			0x04
#define ABK_FIDO_CRED_FLAG_AT			0x40

struct abk_fido_report {
	size_t len;
	u8 data[ABK_FIDO_REPORT_LEN];
};

struct abk_fido_queue {
	spinlock_t lock;
	wait_queue_head_t wait;
	unsigned int head;
	unsigned int tail;
	unsigned int count;
	struct abk_fido_report items[ABK_FIDO_QUEUE_DEPTH];
};

struct abk_fido_channel {
	bool in_use;
	bool cancelled;
	u32 cid;
	u8 cmd;
	u8 next_seq;
	u16 expected_len;
	u16 received_len;
	u8 msg[ABK_FIDO_MAX_MSG];
};

struct abk_fido_credential {
	bool in_use;
	bool resident;
	u8 cred_id[32];
	u8 user_id[ABK_FIDO_MAX_USER_ID];
	u8 user_id_len;
	char rp_id[ABK_FIDO_MAX_RP_ID];
	char user_name[ABK_FIDO_MAX_USER_NAME];
	char user_display[ABK_FIDO_MAX_USER_NAME];
	u8 priv_key[32];
	u8 pub_key[64];
};

struct abk_fido_store {
	bool pin_set;
	u8 aaguid[16];
	u8 pin_hash[16];
	u8 pin_token[32];
	u8 pin_retries;
	u32 sign_count;
	struct abk_fido_credential creds[ABK_FIDO_MAX_CREDS];
};

struct abk_fido_store_disk_cred {
	u8 in_use;
	u8 resident;
	u8 user_id_len;
	u8 reserved0;
	u8 cred_id[32];
	u8 user_id[ABK_FIDO_MAX_USER_ID];
	char rp_id[ABK_FIDO_MAX_RP_ID];
	char user_name[ABK_FIDO_MAX_USER_NAME];
	char user_display[ABK_FIDO_MAX_USER_NAME];
	u8 priv_key[32];
	u8 pub_key[64];
};

struct abk_fido_store_disk {
	u32 magic;
	u32 version;
	u32 crc32;
	u32 sign_count;
	u8 aaguid[16];
	u8 pin_set;
	u8 pin_retries;
	u8 reserved1[2];
	u8 pin_hash[16];
	u8 pin_token[32];
	struct abk_fido_store_disk_cred creds[ABK_FIDO_MAX_CREDS];
};

struct abk_fido_slice {
	const u8 *ptr;
	size_t len;
};

struct abk_cbor_reader {
	const u8 *buf;
	size_t len;
	size_t pos;
};

struct abk_cbor_writer {
	u8 *buf;
	size_t len;
	size_t pos;
	int err;
};

struct abk_fido_pin_key_agreement {
	bool present;
	u8 pub_key[64];
};

struct abk_fido_make_cred_req {
	bool have_client_data_hash;
	bool have_rp_id;
	bool have_user_id;
	bool rk;
	bool uv;
	u8 client_data_hash[32];
	char rp_id[ABK_FIDO_MAX_RP_ID];
	u8 user_id[ABK_FIDO_MAX_USER_ID];
	u8 user_id_len;
	char user_name[ABK_FIDO_MAX_USER_NAME];
	char user_display[ABK_FIDO_MAX_USER_NAME];
	struct {
		bool present;
		u8 id[32];
		size_t len;
	} exclude[8];
	unsigned int exclude_count;
};

struct abk_fido_get_assert_req {
	bool have_client_data_hash;
	bool have_rp_id;
	bool uv;
	u8 client_data_hash[32];
	char rp_id[ABK_FIDO_MAX_RP_ID];
	struct {
		bool present;
		u8 id[32];
		size_t len;
	} allow[8];
	unsigned int allow_count;
};

struct abk_fido_client_pin_req {
	u8 protocol;
	u8 subcommand;
	struct abk_fido_pin_key_agreement key_agreement;
	struct abk_fido_slice pin_auth;
	struct abk_fido_slice new_pin_enc;
	struct abk_fido_slice pin_hash_enc;
};

struct abk_fido_usb;

struct abk_fido_device {
	struct mutex lock;
	struct abk_fido_store store;
	struct abk_fido_channel channels[ABK_FIDO_MAX_CHANNELS];
	bool store_loaded;
	bool store_dirty;
	bool bound;
	u32 next_cid;
	u32 store_generation;
	char hid_name[16];
	char udc_name[64];
	char last_error[160];
	char last_trace[256];
	wait_queue_head_t auth_wait;
	bool auth_gate_enabled;
	bool auth_pending;
	bool auth_decided;
	bool auth_allowed;
	u32 auth_request_id;
	u8 auth_pending_ctap_cmd;
	bool auth_pending_uv;
	bool auth_pending_rk;
	char auth_pending_rp_id[ABK_FIDO_MAX_RP_ID];
	bool auth_cache_valid;
	unsigned long auth_cache_expires;
	u8 *store_blob_staging;
	size_t store_blob_staging_len;
	u8 pin_agreement_priv[32];
	u8 pin_agreement_pub[64];
	bool pin_agreement_valid;
	struct abk_fido_usb *usb;
	struct kobject *kobj;
};

struct abk_fido_opts {
	struct usb_function_instance func_inst;
	int minor;
};

struct abk_fido_usb {
	struct usb_function func;
	struct usb_ep *in_ep;
	struct usb_ep *out_ep;
	struct usb_request *in_req;
	struct usb_request *out_req[4];
	spinlock_t tx_lock;
	bool tx_pending;
	bool online;
	struct work_struct rx_work;
	struct abk_fido_queue rx_packets;
	struct abk_fido_queue debug_rx;
	struct abk_fido_queue tx_packets;
	struct miscdevice miscdev;
	bool misc_registered;
	char misc_name[16];
	struct abk_fido_device *owner;
	u8 idle;
	u8 protocol;
	bool userspace;
};

static struct abk_fido_device abk_fido_dev = {
	.lock = __MUTEX_INITIALIZER(abk_fido_dev.lock),
	.next_cid = 1,
};

/* A transport-independent CTAP HID endpoint for local consumers (Credential
 * Manager provider and the desktop LAN bridge).  It uses the exact same
 * 64-byte CTAP HID framing as the USB gadget, but never touches USB queues.
 */
static struct abk_fido_usb abk_fido_user_usb;
static bool abk_fido_user_registered;
static bool abk_fido_usb_registered;

static DEFINE_IDA(abk_fido_ida);
static DEFINE_MUTEX(abk_fido_ida_lock);

static const u8 abk_fido_report_desc[ABK_FIDO_REPORT_DESC_LEN] = {
	0x06, 0xd0, 0xf1,
	0x09, 0x01,
	0xa1, 0x01,
	0x09, 0x20,
	0x15, 0x00,
	0x26, 0xff, 0x00,
	0x75, 0x08,
	0x95, 0x40,
	0x81, 0x02,
	0x09, 0x21,
	0x15, 0x00,
	0x26, 0xff, 0x00,
	0x75, 0x08,
	0x95, 0x40,
	0x91, 0x02,
	0xc0,
};

static struct usb_interface_descriptor abk_fido_intf_desc = {
	.bLength = sizeof(abk_fido_intf_desc),
	.bDescriptorType = USB_DT_INTERFACE,
	.bAlternateSetting = 0,
	.bNumEndpoints = 2,
	.bInterfaceClass = USB_CLASS_HID,
	.bInterfaceSubClass = 0,
	.bInterfaceProtocol = 0,
};

static struct hid_descriptor abk_fido_hid_desc = {
	.bLength = sizeof(abk_fido_hid_desc),
	.bDescriptorType = HID_DT_HID,
	.bcdHID = cpu_to_le16(0x0111),
	.bCountryCode = 0,
	.bNumDescriptors = 1,
};

static struct usb_endpoint_descriptor abk_fido_fs_in_desc = {
	.bLength = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType = USB_DT_ENDPOINT,
	.bEndpointAddress = USB_DIR_IN,
	.bmAttributes = USB_ENDPOINT_XFER_INT,
	.wMaxPacketSize = cpu_to_le16(ABK_FIDO_REPORT_LEN),
	.bInterval = 5,
};

static struct usb_endpoint_descriptor abk_fido_fs_out_desc = {
	.bLength = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType = USB_DT_ENDPOINT,
	.bEndpointAddress = USB_DIR_OUT,
	.bmAttributes = USB_ENDPOINT_XFER_INT,
	.wMaxPacketSize = cpu_to_le16(ABK_FIDO_REPORT_LEN),
	.bInterval = 5,
};

static struct usb_endpoint_descriptor abk_fido_hs_in_desc = {
	.bLength = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType = USB_DT_ENDPOINT,
	.bEndpointAddress = USB_DIR_IN,
	.bmAttributes = USB_ENDPOINT_XFER_INT,
	.wMaxPacketSize = cpu_to_le16(ABK_FIDO_REPORT_LEN),
	.bInterval = 4,
};

static struct usb_endpoint_descriptor abk_fido_hs_out_desc = {
	.bLength = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType = USB_DT_ENDPOINT,
	.bEndpointAddress = USB_DIR_OUT,
	.bmAttributes = USB_ENDPOINT_XFER_INT,
	.wMaxPacketSize = cpu_to_le16(ABK_FIDO_REPORT_LEN),
	.bInterval = 4,
};

static struct usb_endpoint_descriptor abk_fido_ss_in_desc = {
	.bLength = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType = USB_DT_ENDPOINT,
	.bEndpointAddress = USB_DIR_IN,
	.bmAttributes = USB_ENDPOINT_XFER_INT,
	.wMaxPacketSize = cpu_to_le16(ABK_FIDO_REPORT_LEN),
	.bInterval = 4,
};

static struct usb_ss_ep_comp_descriptor abk_fido_ss_in_comp = {
	.bLength = sizeof(abk_fido_ss_in_comp),
	.bDescriptorType = USB_DT_SS_ENDPOINT_COMP,
	.wBytesPerInterval = cpu_to_le16(ABK_FIDO_REPORT_LEN),
};

static struct usb_endpoint_descriptor abk_fido_ss_out_desc = {
	.bLength = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType = USB_DT_ENDPOINT,
	.bEndpointAddress = USB_DIR_OUT,
	.bmAttributes = USB_ENDPOINT_XFER_INT,
	.wMaxPacketSize = cpu_to_le16(ABK_FIDO_REPORT_LEN),
	.bInterval = 4,
};

static struct usb_ss_ep_comp_descriptor abk_fido_ss_out_comp = {
	.bLength = sizeof(abk_fido_ss_out_comp),
	.bDescriptorType = USB_DT_SS_ENDPOINT_COMP,
	.wBytesPerInterval = cpu_to_le16(ABK_FIDO_REPORT_LEN),
};

static struct usb_string abk_fido_strings[] = {
	{ .s = "ABK Security Key" },
	{ },
};

static struct usb_gadget_strings abk_fido_stringtab = {
	.language = 0x0409,
	.strings = abk_fido_strings,
};

static struct usb_gadget_strings *abk_fido_func_strings[] = {
	&abk_fido_stringtab,
	NULL,
};

static void abk_fido_set_last_trace_locked(const char *fmt, ...);
static int abk_fido_store_from_disk_into(struct abk_fido_store_disk *disk,
					 struct abk_fido_store *store,
					 char *reason, size_t reason_len);
static void abk_fido_store_to_disk(struct abk_fido_store_disk *disk);
static void abk_fido_finalize_restored_store_locked(const char *success_trace);
static int abk_fido_load_store_locked(void);
static int abk_fido_read_store_from_path_locked(const char *path,
						struct abk_fido_store *store,
						char *reason, size_t reason_len);
static int abk_fido_restore_persisted_store_locked(const char *source);
static int abk_fido_write_store_to_path_locked(const char *path,
					       const struct abk_fido_store_disk *disk,
					       char *reason, size_t reason_len);

enum {
	ABK_FIDO_STRING_INTERFACE = 0,
};

static struct usb_descriptor_header *abk_fido_fs_descs[] = {
	(struct usb_descriptor_header *)&abk_fido_intf_desc,
	(struct usb_descriptor_header *)&abk_fido_hid_desc,
	(struct usb_descriptor_header *)&abk_fido_fs_in_desc,
	(struct usb_descriptor_header *)&abk_fido_fs_out_desc,
	NULL,
};

static struct usb_descriptor_header *abk_fido_hs_descs[] = {
	(struct usb_descriptor_header *)&abk_fido_intf_desc,
	(struct usb_descriptor_header *)&abk_fido_hid_desc,
	(struct usb_descriptor_header *)&abk_fido_hs_in_desc,
	(struct usb_descriptor_header *)&abk_fido_hs_out_desc,
	NULL,
};

static struct usb_descriptor_header *abk_fido_ss_descs[] = {
	(struct usb_descriptor_header *)&abk_fido_intf_desc,
	(struct usb_descriptor_header *)&abk_fido_hid_desc,
	(struct usb_descriptor_header *)&abk_fido_ss_in_desc,
	(struct usb_descriptor_header *)&abk_fido_ss_in_comp,
	(struct usb_descriptor_header *)&abk_fido_ss_out_desc,
	(struct usb_descriptor_header *)&abk_fido_ss_out_comp,
	NULL,
};

static void abk_fido_queue_init(struct abk_fido_queue *queue)
{
	spin_lock_init(&queue->lock);
	init_waitqueue_head(&queue->wait);
	queue->head = 0;
	queue->tail = 0;
	queue->count = 0;
}

static bool abk_fido_queue_push(struct abk_fido_queue *queue,
				const u8 *data, size_t len)
{
	unsigned long flags;
	struct abk_fido_report *slot;

	if (!data || !len || len > ABK_FIDO_REPORT_LEN)
		return false;

	spin_lock_irqsave(&queue->lock, flags);
	if (queue->count == ABK_FIDO_QUEUE_DEPTH) {
		spin_unlock_irqrestore(&queue->lock, flags);
		return false;
	}

	slot = &queue->items[queue->tail];
	memset(slot, 0, sizeof(*slot));
	memcpy(slot->data, data, len);
	slot->len = len;
	queue->tail = (queue->tail + 1) % ABK_FIDO_QUEUE_DEPTH;
	queue->count++;
	spin_unlock_irqrestore(&queue->lock, flags);
	wake_up_interruptible(&queue->wait);
	return true;
}

static bool abk_fido_queue_pop(struct abk_fido_queue *queue,
			       struct abk_fido_report *out)
{
	unsigned long flags;

	spin_lock_irqsave(&queue->lock, flags);
	if (!queue->count) {
		spin_unlock_irqrestore(&queue->lock, flags);
		return false;
	}

	*out = queue->items[queue->head];
	queue->head = (queue->head + 1) % ABK_FIDO_QUEUE_DEPTH;
	queue->count--;
	spin_unlock_irqrestore(&queue->lock, flags);
	return true;
}

static bool abk_fido_queue_empty(struct abk_fido_queue *queue)
{
	unsigned long flags;
	bool empty;

	spin_lock_irqsave(&queue->lock, flags);
	empty = queue->count == 0;
	spin_unlock_irqrestore(&queue->lock, flags);
	return empty;
}

static int abk_fido_shash_digest(const char *alg,
				 const u8 *data, size_t len,
				 u8 *out, size_t out_len)
{
	struct crypto_shash *tfm;
	struct shash_desc *desc;
	int ret;
	size_t size;

	tfm = crypto_alloc_shash(alg, 0, 0);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	size = sizeof(*desc) + crypto_shash_descsize(tfm);
	desc = kzalloc(size, GFP_KERNEL);
	if (!desc) {
		crypto_free_shash(tfm);
		return -ENOMEM;
	}

	desc->tfm = tfm;
	ret = crypto_shash_digest(desc, data, len, out);
	kfree(desc);
	crypto_free_shash(tfm);
	return ret;
}

static int abk_fido_sha256(const u8 *data, size_t len, u8 out[SHA256_DIGEST_SIZE])
{
	return abk_fido_shash_digest("sha256", data, len, out, SHA256_DIGEST_SIZE);
}

static void abk_fido_bootstrap_companion_service(void)
{
	static char *argv[] = {
		"/system/bin/am",
		"start-foreground-service",
		"-n",
		"com.abk.extension.fido/.FidoSyncService",
		"--es",
		"reason",
		"kernel_boot",
		NULL,
	};
	static char *envp[] = {
		"HOME=/",
		"PATH=/system/bin:/system/xbin:/vendor/bin:/vendor/xbin",
		NULL,
	};
	int ret;

	ret = call_usermodehelper(argv[0], argv, envp, UMH_NO_WAIT);
	pr_info("abk_fido_key: bootstrap companion service ret=%d\n", ret);
}

static ssize_t abk_fido_store_blob_read(struct file *filp, struct kobject *kobj,
					struct bin_attribute *attr, char *buf,
					loff_t off, size_t count)
{
	struct abk_fido_store_disk *disk;
	ssize_t ret;
	size_t size = sizeof(*disk);

	if (off >= size)
		return 0;
	count = min(count, size - (size_t)off);

	disk = kvzalloc(sizeof(*disk), GFP_KERNEL);
	if (!disk)
		return -ENOMEM;

	mutex_lock(&abk_fido_dev.lock);
	ret = abk_fido_load_store_locked();
	if (ret && ret != -ENOENT) {
		mutex_unlock(&abk_fido_dev.lock);
		kvfree(disk);
		return ret;
	}
	abk_fido_store_to_disk(disk);
	mutex_unlock(&abk_fido_dev.lock);

	memcpy(buf, ((u8 *)disk) + off, count);
	kvfree(disk);
	return count;
}

static ssize_t abk_fido_store_blob_write(struct file *filp, struct kobject *kobj,
					 struct bin_attribute *attr, char *buf,
					 loff_t off, size_t count)
{
	struct abk_fido_store_disk *disk;
	size_t size = sizeof(*disk);
	int ret;
	char reason[96] = "";

	if (off < 0 || off >= size || count > size - off)
		return -EINVAL;

	mutex_lock(&abk_fido_dev.lock);
	if (!abk_fido_dev.store_blob_staging) {
		abk_fido_dev.store_blob_staging = kvzalloc(size, GFP_KERNEL);
		abk_fido_dev.store_blob_staging_len = 0;
	}
	if (!abk_fido_dev.store_blob_staging) {
		mutex_unlock(&abk_fido_dev.lock);
		return -ENOMEM;
	}

	memcpy(abk_fido_dev.store_blob_staging + off, buf, count);
	abk_fido_dev.store_blob_staging_len = max_t(size_t,
		abk_fido_dev.store_blob_staging_len, off + count);

	if (abk_fido_dev.store_blob_staging_len == size) {
		disk = (struct abk_fido_store_disk *)abk_fido_dev.store_blob_staging;
		ret = abk_fido_store_from_disk_into(disk, &abk_fido_dev.store,
						    reason, sizeof(reason));
		if (!ret) {
			abk_fido_dev.store_loaded = true;
			abk_fido_dev.store_generation++;
			abk_fido_finalize_restored_store_locked(
				"store blob restored from userspace");
			pr_info("abk_fido_key: store blob restored from userspace\n");
		} else {
			snprintf(abk_fido_dev.last_error, sizeof(abk_fido_dev.last_error),
				 "%s", reason[0] ? reason :
				 "store blob restore failed");
			abk_fido_set_last_trace_locked("store blob restore failed: %s",
				reason[0] ? reason : "validation failed");
			pr_warn("abk_fido_key: store blob restore failed: %s\n",
				reason[0] ? reason : "validation failed");
		}
		kvfree(abk_fido_dev.store_blob_staging);
		abk_fido_dev.store_blob_staging = NULL;
		abk_fido_dev.store_blob_staging_len = 0;
		mutex_unlock(&abk_fido_dev.lock);
		return ret ? ret : count;
	}
	mutex_unlock(&abk_fido_dev.lock);
	return count;
}

static struct file *abk_fido_filp_open_kernel(const char *path, int flags, umode_t mode)
{
	const struct cred *old;
	struct cred *cred;
	struct file *file;

	cred = prepare_kernel_cred(NULL);
	if (!cred)
		return ERR_PTR(-ENOMEM);

	old = override_creds(cred);
	file = filp_open(path, flags, mode);
	revert_creds(old);
	return file;
}

static ssize_t abk_fido_kernel_read(struct file *file, void *buf, size_t len, loff_t *pos)
{
	const struct cred *old;
	struct cred *cred;
	ssize_t ret;

	cred = prepare_kernel_cred(NULL);
	if (!cred)
		return -ENOMEM;

	old = override_creds(cred);
	ret = kernel_read(file, buf, len, pos);
	revert_creds(old);
	return ret;
}

static ssize_t abk_fido_kernel_write(struct file *file, const void *buf, size_t len, loff_t *pos)
{
	const struct cred *old;
	struct cred *cred;
	ssize_t ret;

	cred = prepare_kernel_cred(NULL);
	if (!cred)
		return -ENOMEM;

	old = override_creds(cred);
	ret = kernel_write(file, buf, len, pos);
	revert_creds(old);
	return ret;
}

static int abk_fido_aes256_cbc(bool encrypt, const u8 key[32], u8 *buf, size_t len)
{
	struct crypto_skcipher *tfm;
	struct skcipher_request *req;
	DECLARE_CRYPTO_WAIT(wait);
	struct scatterlist sg;
	u8 iv[16] = {};
	int ret;

	if (!len || (len % 16))
		return -EINVAL;

	tfm = crypto_alloc_skcipher("cbc(aes)", 0, 0);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	ret = crypto_skcipher_setkey(tfm, key, 32);
	if (ret)
		goto out_tfm;

	req = skcipher_request_alloc(tfm, GFP_KERNEL);
	if (!req) {
		ret = -ENOMEM;
		goto out_tfm;
	}

	skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_SLEEP,
				      crypto_req_done, &wait);
	sg_init_one(&sg, buf, len);
	skcipher_request_set_crypt(req, &sg, &sg, len, iv);
	ret = crypto_wait_req(encrypt ? crypto_skcipher_encrypt(req)
				      : crypto_skcipher_decrypt(req), &wait);
	skcipher_request_free(req);
out_tfm:
	crypto_free_skcipher(tfm);
	return ret;
}

static void abk_fido_digits_from_bytes(const u8 *bytes, size_t len,
				       u64 *digits, unsigned int ndigits)
{
	int diff = ndigits - DIV_ROUND_UP(len, sizeof(u64));
	unsigned int rem = len & 7;
	__be64 msd = 0;

	if (diff > 0) {
		ndigits -= diff;
		memset(&digits[ndigits - 1], 0, diff * sizeof(u64));
	}

	if (rem) {
		memcpy((u8 *)&msd + sizeof(msd) - rem, bytes, rem);
		digits[--ndigits] = be64_to_cpu(msd);
		bytes += rem;
	}

	ecc_swap_digits(bytes, digits, ndigits);
}

static void abk_fido_digits_to_bytes(const u64 *digits, unsigned int ndigits,
				     u8 *out, size_t out_len)
{
	unsigned int i;

	memset(out, 0, out_len);
	for (i = 0; i < ndigits; i++) {
		__be64 word = cpu_to_be64(digits[ndigits - 1 - i]);
		memcpy(out + (i * sizeof(word)), &word, sizeof(word));
	}
}

static void abk_fido_p256_scalar_to_bytes(const u64 *digits, u8 out[32])
{
	memcpy(out, digits, 32);
}

static void abk_fido_p256_scalar_from_bytes(const u8 bytes[32], u64 *digits)
{
	abk_fido_digits_from_bytes(bytes, 32, digits, ECC_CURVE_NIST_P256_DIGITS);
}

static void abk_fido_p256_pub_to_bytes(const u64 *digits, u8 out[64])
{
	memcpy(out, digits, 64);
}

static void abk_fido_p256_pub_from_bytes(const u8 bytes[64], u64 *digits)
{
	abk_fido_digits_from_bytes(bytes, 32, digits, ECC_CURVE_NIST_P256_DIGITS);
	abk_fido_digits_from_bytes(bytes + 32, 32,
				   digits + ECC_CURVE_NIST_P256_DIGITS,
				   ECC_CURVE_NIST_P256_DIGITS);
}

static u64 abk_fido_vli_add(u64 *result, const u64 *left, const u64 *right,
			    unsigned int ndigits)
{
	u64 carry = 0;
	unsigned int i;

	for (i = 0; i < ndigits; i++) {
		u64 prev = left[i] + carry;
		u64 sum = prev + right[i];

		carry = (prev < left[i]) || (sum < prev);
		result[i] = sum;
	}
	return carry;
}

static void abk_fido_vli_mod_add(u64 *result, const u64 *left, const u64 *right,
				 const u64 *mod, unsigned int ndigits)
{
	u64 carry;

	carry = abk_fido_vli_add(result, left, right, ndigits);
	if (carry || vli_cmp(result, mod, ndigits) >= 0)
		vli_sub(result, result, mod, ndigits);
}

static int abk_fido_ecdsa_sign_p256(const u8 priv_bytes[32], const u8 hash_bytes[32],
				    u8 sig_der[ABK_FIDO_MAX_SIG_DER], size_t *sig_len)
{
	const struct ecc_curve *curve = ecc_get_curve(ECC_CURVE_NIST_P256);
	const unsigned int ndigits = ECC_CURVE_NIST_P256_DIGITS;
	u64 d[ECC_MAX_DIGITS] = {};
	u64 z[ECC_MAX_DIGITS] = {};
	u64 k[ECC_MAX_DIGITS] = {};
	u64 k_int[ECC_MAX_DIGITS] = {};
	u64 r[ECC_MAX_DIGITS] = {};
	u64 s[ECC_MAX_DIGITS] = {};
	u64 kinv[ECC_MAX_DIGITS] = {};
	u64 rd[ECC_MAX_DIGITS] = {};
	u64 sum[ECC_MAX_DIGITS] = {};
	u64 pub[ECC_MAX_DIGITS * 2] = {};
	u8 raw_rs[64];
	u8 *r_bytes = raw_rs;
	u8 *s_bytes = raw_rs + 32;
	u8 enc_r[33];
	u8 enc_s[33];
	size_t r_len = 32, s_len = 32;
	int ret;
	unsigned int tries;

	if (!curve || !sig_len)
		return -EINVAL;

	abk_fido_digits_from_bytes(priv_bytes, 32, d, ndigits);
	abk_fido_digits_from_bytes(hash_bytes, 32, z, ndigits);

	for (tries = 0; tries < 16; tries++) {
		ret = ecc_gen_privkey(ECC_CURVE_NIST_P256, ndigits, k);
		if (ret)
			return ret;

		ret = ecc_make_pub_key(ECC_CURVE_NIST_P256, ndigits, k, pub);
		if (ret)
			continue;

		abk_fido_digits_from_bytes((const u8 *)pub, 32, r, ndigits);
		while (vli_cmp(r, curve->n, ndigits) >= 0)
			vli_sub(r, r, curve->n, ndigits);
		if (vli_is_zero(r, ndigits))
			continue;

		vli_mod_mult_slow(rd, r, d, curve->n, ndigits);
		abk_fido_vli_mod_add(sum, z, rd, curve->n, ndigits);
		if (vli_is_zero(sum, ndigits))
			continue;

		abk_fido_digits_from_bytes((const u8 *)k, 32, k_int, ndigits);
		vli_mod_inv(kinv, k_int, curve->n, ndigits);
		vli_mod_mult_slow(s, kinv, sum, curve->n, ndigits);
		if (!vli_is_zero(s, ndigits))
			break;
	}

	if (tries == 16)
		return -EAGAIN;

	abk_fido_digits_to_bytes(r, ndigits, r_bytes, 32);
	abk_fido_digits_to_bytes(s, ndigits, s_bytes, 32);

	memcpy(enc_r + 1, r_bytes, 32);
	memcpy(enc_s + 1, s_bytes, 32);
	if (enc_r[1] & 0x80) {
		enc_r[0] = 0x00;
		r_len = 33;
	} else {
		memmove(enc_r, enc_r + 1, 32);
		r_len = 32;
	}
	if (enc_s[1] & 0x80) {
		enc_s[0] = 0x00;
		s_len = 33;
	} else {
		memmove(enc_s, enc_s + 1, 32);
		s_len = 32;
	}

	while (r_len > 1 && enc_r[0] == 0x00 && !(enc_r[1] & 0x80)) {
		memmove(enc_r, enc_r + 1, --r_len);
	}
	while (s_len > 1 && enc_s[0] == 0x00 && !(enc_s[1] & 0x80)) {
		memmove(enc_s, enc_s + 1, --s_len);
	}

	if (6 + r_len + s_len > ABK_FIDO_MAX_SIG_DER)
		return -EOVERFLOW;

	sig_der[0] = 0x30;
	sig_der[1] = 4 + r_len + s_len;
	sig_der[2] = 0x02;
	sig_der[3] = r_len;
	memcpy(sig_der + 4, enc_r, r_len);
	sig_der[4 + r_len] = 0x02;
	sig_der[5 + r_len] = s_len;
	memcpy(sig_der + 6 + r_len, enc_s, s_len);
	*sig_len = 6 + r_len + s_len;
	return 0;
}

static bool abk_fido_slice_eq_text(struct abk_fido_slice slice, const char *text)
{
	size_t len = strlen(text);

	return slice.len == len && !memcmp(slice.ptr, text, len);
}

static int abk_cbor_read_u64(struct abk_cbor_reader *r, u8 ai, u64 *value)
{
	u64 v = 0;

	switch (ai) {
	case 0 ... 23:
		v = ai;
		break;
	case 24:
		if (r->pos + 1 > r->len)
			return -EINVAL;
		v = r->buf[r->pos++];
		break;
	case 25:
		if (r->pos + 2 > r->len)
			return -EINVAL;
		v = get_unaligned_be16(r->buf + r->pos);
		r->pos += 2;
		break;
	case 26:
		if (r->pos + 4 > r->len)
			return -EINVAL;
		v = get_unaligned_be32(r->buf + r->pos);
		r->pos += 4;
		break;
	case 27:
		if (r->pos + 8 > r->len)
			return -EINVAL;
		v = get_unaligned_be64(r->buf + r->pos);
		r->pos += 8;
		break;
	default:
		return -EINVAL;
	}

	if (value)
		*value = v;
	return 0;
}

static int abk_cbor_read_head(struct abk_cbor_reader *r, u8 *major, u64 *value)
{
	u8 byte;
	u8 ai;

	if (r->pos >= r->len)
		return -EINVAL;
	byte = r->buf[r->pos++];
	*major = byte >> 5;
	ai = byte & 0x1f;
	return abk_cbor_read_u64(r, ai, value);
}

static int abk_cbor_read_uint(struct abk_cbor_reader *r, u64 *value)
{
	u8 major;
	u64 tmp;
	int ret;

	ret = abk_cbor_read_head(r, &major, &tmp);
	if (ret)
		return ret;
	if (major != 0)
		return -EINVAL;
	*value = tmp;
	return 0;
}

static int abk_cbor_read_int(struct abk_cbor_reader *r, s64 *value)
{
	u8 major;
	u64 tmp;
	int ret;

	ret = abk_cbor_read_head(r, &major, &tmp);
	if (ret)
		return ret;
	if (major == 0)
		*value = (s64)tmp;
	else if (major == 1)
		*value = -1 - (s64)tmp;
	else
		return -EINVAL;
	return 0;
}

static int abk_cbor_read_bytes(struct abk_cbor_reader *r, struct abk_fido_slice *slice)
{
	u8 major;
	u64 len;
	int ret;

	ret = abk_cbor_read_head(r, &major, &len);
	if (ret)
		return ret;
	if (major != 2 || r->pos + len > r->len)
		return -EINVAL;
	slice->ptr = r->buf + r->pos;
	slice->len = len;
	r->pos += len;
	return 0;
}

static int abk_cbor_read_text(struct abk_cbor_reader *r, struct abk_fido_slice *slice)
{
	u8 major;
	u64 len;
	int ret;

	ret = abk_cbor_read_head(r, &major, &len);
	if (ret)
		return ret;
	if (major != 3 || r->pos + len > r->len)
		return -EINVAL;
	slice->ptr = r->buf + r->pos;
	slice->len = len;
	r->pos += len;
	return 0;
}

static int abk_cbor_read_bool(struct abk_cbor_reader *r, bool *value)
{
	u8 major;
	u64 len;
	int ret;

	ret = abk_cbor_read_head(r, &major, &len);
	if (ret)
		return ret;
	if (major != 7 || (len != 20 && len != 21))
		return -EINVAL;
	*value = len == 21;
	return 0;
}

static int abk_cbor_read_map(struct abk_cbor_reader *r, u64 *count)
{
	u8 major;
	u64 len;
	int ret;

	ret = abk_cbor_read_head(r, &major, &len);
	if (ret)
		return ret;
	if (major != 5)
		return -EINVAL;
	*count = len;
	return 0;
}

static int abk_cbor_read_array(struct abk_cbor_reader *r, u64 *count)
{
	u8 major;
	u64 len;
	int ret;

	ret = abk_cbor_read_head(r, &major, &len);
	if (ret)
		return ret;
	if (major != 4)
		return -EINVAL;
	*count = len;
	return 0;
}

static int abk_cbor_skip(struct abk_cbor_reader *r)
{
	u8 major;
	u64 len;
	int ret;
	u64 i;

	ret = abk_cbor_read_head(r, &major, &len);
	if (ret)
		return ret;

	switch (major) {
	case 0:
	case 1:
	case 7:
		return 0;
	case 2:
	case 3:
		if (r->pos + len > r->len)
			return -EINVAL;
		r->pos += len;
		return 0;
	case 4:
		for (i = 0; i < len; i++) {
			ret = abk_cbor_skip(r);
			if (ret)
				return ret;
		}
		return 0;
	case 5:
		for (i = 0; i < len; i++) {
			ret = abk_cbor_skip(r);
			if (ret)
				return ret;
			ret = abk_cbor_skip(r);
			if (ret)
				return ret;
		}
		return 0;
	default:
		return -EINVAL;
	}
}

static void abk_cbor_writer_init(struct abk_cbor_writer *w, u8 *buf, size_t len)
{
	w->buf = buf;
	w->len = len;
	w->pos = 0;
	w->err = 0;
}

static void abk_cbor_put_head(struct abk_cbor_writer *w, u8 major, u64 value)
{
	if (w->err)
		return;

	if (value <= 23) {
		if (w->pos + 1 > w->len)
			goto overflow;
		w->buf[w->pos++] = (major << 5) | (u8)value;
		return;
	}
	if (value <= 0xff) {
		if (w->pos + 2 > w->len)
			goto overflow;
		w->buf[w->pos++] = (major << 5) | 24;
		w->buf[w->pos++] = (u8)value;
		return;
	}
	if (value <= 0xffff) {
		if (w->pos + 3 > w->len)
			goto overflow;
		w->buf[w->pos++] = (major << 5) | 25;
		put_unaligned_be16((u16)value, w->buf + w->pos);
		w->pos += 2;
		return;
	}
	if (value <= 0xffffffffULL) {
		if (w->pos + 5 > w->len)
			goto overflow;
		w->buf[w->pos++] = (major << 5) | 26;
		put_unaligned_be32((u32)value, w->buf + w->pos);
		w->pos += 4;
		return;
	}
	if (w->pos + 9 > w->len)
		goto overflow;
	w->buf[w->pos++] = (major << 5) | 27;
	put_unaligned_be64(value, w->buf + w->pos);
	w->pos += 8;
	return;
overflow:
	w->err = -EOVERFLOW;
}

static void abk_cbor_put_uint(struct abk_cbor_writer *w, u64 value)
{
	abk_cbor_put_head(w, 0, value);
}

static void abk_cbor_put_int(struct abk_cbor_writer *w, s64 value)
{
	if (value >= 0)
		abk_cbor_put_head(w, 0, value);
	else
		abk_cbor_put_head(w, 1, (u64)(-1 - value));
}

static void abk_cbor_put_bytes(struct abk_cbor_writer *w, const u8 *data, size_t len)
{
	if (w->err)
		return;
	abk_cbor_put_head(w, 2, len);
	if (w->err)
		return;
	if (w->pos + len > w->len) {
		w->err = -EOVERFLOW;
		return;
	}
	memcpy(w->buf + w->pos, data, len);
	w->pos += len;
}

static void abk_cbor_put_text(struct abk_cbor_writer *w, const char *text)
{
	size_t len = strlen(text);

	abk_cbor_put_head(w, 3, len);
	if (w->err)
		return;
	if (w->pos + len > w->len) {
		w->err = -EOVERFLOW;
		return;
	}
	memcpy(w->buf + w->pos, text, len);
	w->pos += len;
}

static void abk_cbor_put_bool(struct abk_cbor_writer *w, bool value)
{
	abk_cbor_put_head(w, 7, value ? 21 : 20);
}

static void abk_cbor_put_map(struct abk_cbor_writer *w, u64 count)
{
	abk_cbor_put_head(w, 5, count);
}

static void abk_cbor_put_array(struct abk_cbor_writer *w, u64 count)
{
	abk_cbor_put_head(w, 4, count);
}

static unsigned int abk_fido_count_credentials_locked(void)
{
	unsigned int i;
	unsigned int count = 0;

	for (i = 0; i < ABK_FIDO_MAX_CREDS; i++) {
		if (abk_fido_dev.store.creds[i].in_use)
			count++;
	}
	return count;
}

static bool abk_fido_bytes_all_zero(const u8 *buf, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++) {
		if (buf[i] != 0)
			return false;
	}
	return true;
}

static bool abk_fido_pin_configured_locked(void)
{
	return abk_fido_dev.store.pin_set &&
	       !abk_fido_bytes_all_zero(abk_fido_dev.store.pin_hash,
					sizeof(abk_fido_dev.store.pin_hash));
}

static u32 abk_fido_store_crc32(const struct abk_fido_store_disk *disk)
{
	u32 crc;
	const u8 *ptr;
	size_t len;

	ptr = (const u8 *)disk + offsetof(struct abk_fido_store_disk, sign_count);
	len = sizeof(*disk) - offsetof(struct abk_fido_store_disk, sign_count);

	crc = crc32_le(~0U, ptr, len);
	return ~crc;
}

static void abk_fido_set_last_trace_locked(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vscnprintf(abk_fido_dev.last_trace, sizeof(abk_fido_dev.last_trace),
		   fmt, args);
	va_end(args);
}

static int abk_fido_store_from_disk_into(struct abk_fido_store_disk *disk,
					 struct abk_fido_store *store,
					 char *reason, size_t reason_len)
{
	unsigned int i;
	u32 crc;
	u32 legacy_crc;

	if (le32_to_cpu(disk->magic) != ABK_FIDO_STORE_MAGIC) {
		if (reason && reason_len)
			scnprintf(reason, reason_len, "invalid store magic 0x%x",
				  le32_to_cpu(disk->magic));
		return -EINVAL;
	}
	if (le32_to_cpu(disk->version) != ABK_FIDO_STORE_VERSION) {
		if (reason && reason_len)
			scnprintf(reason, reason_len, "invalid store version %u",
				  le32_to_cpu(disk->version));
		return -EINVAL;
	}

	crc = abk_fido_store_crc32(disk);
	if (crc != le32_to_cpu(disk->crc32)) {
		legacy_crc = crc32_le(0,
			(u8 *)disk + offsetof(struct abk_fido_store_disk, sign_count),
			sizeof(*disk) - offsetof(struct abk_fido_store_disk, sign_count));
		if (legacy_crc == le32_to_cpu(disk->crc32)) {
			pr_info("abk_fido_key: accepted legacy store crc 0x%08x\n",
				legacy_crc);
		} else {
			if (reason && reason_len)
				scnprintf(reason, reason_len,
					  "invalid store crc stored=0x%08x calc=0x%08x legacy=0x%08x",
					  le32_to_cpu(disk->crc32), crc, legacy_crc);
			return -EILSEQ;
		}
	}

	memset(store, 0, sizeof(*store));
	store->sign_count = le32_to_cpu(disk->sign_count);
	memcpy(store->aaguid, disk->aaguid, sizeof(disk->aaguid));
	store->pin_set = disk->pin_set;
	store->pin_retries = disk->pin_retries;
	memcpy(store->pin_hash, disk->pin_hash, sizeof(disk->pin_hash));
	memcpy(store->pin_token, disk->pin_token, sizeof(disk->pin_token));

	for (i = 0; i < ABK_FIDO_MAX_CREDS; i++) {
		struct abk_fido_store_disk_cred *dc = &disk->creds[i];
		struct abk_fido_credential *sc = &store->creds[i];

		sc->in_use = !!dc->in_use;
		sc->resident = !!dc->resident;
		sc->user_id_len = min_t(u8, dc->user_id_len, ABK_FIDO_MAX_USER_ID);
		memcpy(sc->cred_id, dc->cred_id, sizeof(sc->cred_id));
		memcpy(sc->user_id, dc->user_id, sizeof(sc->user_id));
		memcpy(sc->rp_id, dc->rp_id, sizeof(sc->rp_id));
		sc->rp_id[ABK_FIDO_MAX_RP_ID - 1] = '\0';
		memcpy(sc->user_name, dc->user_name, sizeof(sc->user_name));
		sc->user_name[ABK_FIDO_MAX_USER_NAME - 1] = '\0';
		memcpy(sc->user_display, dc->user_display, sizeof(sc->user_display));
		sc->user_display[ABK_FIDO_MAX_USER_NAME - 1] = '\0';
		memcpy(sc->priv_key, dc->priv_key, sizeof(sc->priv_key));
		memcpy(sc->pub_key, dc->pub_key, sizeof(sc->pub_key));
	}
	return 0;
}

static void abk_fido_store_to_disk(struct abk_fido_store_disk *disk)
{
	unsigned int i;
	u32 crc;

	memset(disk, 0, sizeof(*disk));
	disk->magic = cpu_to_le32(ABK_FIDO_STORE_MAGIC);
	disk->version = cpu_to_le32(ABK_FIDO_STORE_VERSION);
	disk->sign_count = cpu_to_le32(abk_fido_dev.store.sign_count);
	memcpy(disk->aaguid, abk_fido_dev.store.aaguid, sizeof(disk->aaguid));
	disk->pin_set = abk_fido_dev.store.pin_set ? 1 : 0;
	disk->pin_retries = abk_fido_dev.store.pin_retries;
	memcpy(disk->pin_hash, abk_fido_dev.store.pin_hash, sizeof(disk->pin_hash));
	memcpy(disk->pin_token, abk_fido_dev.store.pin_token, sizeof(disk->pin_token));

	for (i = 0; i < ABK_FIDO_MAX_CREDS; i++) {
		struct abk_fido_credential *sc = &abk_fido_dev.store.creds[i];
		struct abk_fido_store_disk_cred *dc = &disk->creds[i];

		dc->in_use = sc->in_use ? 1 : 0;
		dc->resident = sc->resident ? 1 : 0;
		dc->user_id_len = sc->user_id_len;
		memcpy(dc->cred_id, sc->cred_id, sizeof(dc->cred_id));
		memcpy(dc->user_id, sc->user_id, sizeof(dc->user_id));
		strscpy(dc->rp_id, sc->rp_id, sizeof(dc->rp_id));
		strscpy(dc->user_name, sc->user_name, sizeof(dc->user_name));
		strscpy(dc->user_display, sc->user_display, sizeof(dc->user_display));
		memcpy(dc->priv_key, sc->priv_key, sizeof(dc->priv_key));
		memcpy(dc->pub_key, sc->pub_key, sizeof(dc->pub_key));
	}

	crc = abk_fido_store_crc32(disk);
	disk->crc32 = cpu_to_le32(crc);
}

static void abk_fido_finalize_restored_store_locked(const char *success_trace)
{
	abk_fido_dev.store_dirty = false;
	abk_fido_dev.last_error[0] = '\0';

	if (abk_fido_dev.store.pin_set &&
	    !abk_fido_pin_configured_locked()) {
		abk_fido_dev.store.pin_set = false;
		abk_fido_dev.store.pin_retries = ABK_FIDO_PIN_RETRIES_DEFAULT;
		abk_fido_dev.store_dirty = true;
		snprintf(abk_fido_dev.last_error, sizeof(abk_fido_dev.last_error),
			 "invalid pin state recovered");
		abk_fido_set_last_trace_locked(
			"%s; cleared invalid pin state", success_trace);
		return;
	}

	abk_fido_set_last_trace_locked("%s", success_trace);
}

static int abk_fido_init_new_store_locked(void)
{
	memset(&abk_fido_dev.store, 0, sizeof(abk_fido_dev.store));
	get_random_bytes(abk_fido_dev.store.aaguid, sizeof(abk_fido_dev.store.aaguid));
	get_random_bytes(abk_fido_dev.store.pin_token, sizeof(abk_fido_dev.store.pin_token));
	abk_fido_dev.store.pin_retries = ABK_FIDO_PIN_RETRIES_DEFAULT;
	abk_fido_dev.store_dirty = true;
	return 0;
}

static int abk_fido_load_store_locked(void)
{
	int ret = -ENOENT;
	char reason[96] = "";

	if (abk_fido_dev.store_loaded)
		return 0;

	if (!ABK_FIDO_PERSIST_ENABLED) {
		abk_fido_dev.store_loaded = true;
		return abk_fido_init_new_store_locked();
	}

	pr_info("abk_fido_key: store load trying %s\n", ABK_FIDO_STORE_PATH);
	ret = abk_fido_read_store_from_path_locked(
		ABK_FIDO_STORE_PATH, &abk_fido_dev.store, reason, sizeof(reason));
	if (!ret) {
		pr_info("abk_fido_key: store load succeeded from %s\n", ABK_FIDO_STORE_PATH);
		abk_fido_finalize_restored_store_locked(
			"store loaded from /metadata/abk_fido_store.bin");
		abk_fido_dev.store_loaded = true;
		abk_fido_dev.store_generation++;
		return 0;
	}
	pr_warn("abk_fido_key: store load failed path=%s ret=%d reason=%s\n",
		ABK_FIDO_STORE_PATH, ret, reason[0] ? reason : "unknown");

	abk_fido_dev.store_loaded = true;
	ret = abk_fido_init_new_store_locked();
	if (ret)
		return ret;

	if (ret == -ENOENT) {
		abk_fido_dev.last_error[0] = '\0';
		abk_fido_set_last_trace_locked(
			"no persisted store found, initialized new store");
	} else {
		snprintf(abk_fido_dev.last_error, sizeof(abk_fido_dev.last_error),
			 "%s, reinitialized", reason[0] ? reason :
			 "store blob invalid");
		abk_fido_set_last_trace_locked("store load failed: %s",
			reason[0] ? reason : "store blob invalid");
	}
	abk_fido_dev.store_generation++;
	return 0;
}

static int abk_fido_maybe_persist_locked(void)
{
	struct abk_fido_store_disk *disk;
	int ret = 0;
	char reason[96] = "";

	if (!abk_fido_dev.store_dirty)
		return 0;

	if (!ABK_FIDO_PERSIST_ENABLED) {
		abk_fido_dev.store_dirty = false;
		return 0;
	}

	disk = kzalloc(sizeof(*disk), GFP_KERNEL);
	if (!disk)
		goto defer_persist;

	abk_fido_store_to_disk(disk);

	pr_info("abk_fido_key: persist trying %s\n", ABK_FIDO_STORE_PATH);
	ret = abk_fido_write_store_to_path_locked(
		ABK_FIDO_STORE_PATH, disk, reason, sizeof(reason));
	if (!ret) {
		pr_info("abk_fido_key: persist succeeded to %s\n", ABK_FIDO_STORE_PATH);
		abk_fido_dev.store_dirty = false;
		abk_fido_dev.store_generation++;
		abk_fido_dev.last_error[0] = '\0';
		abk_fido_set_last_trace_locked("persisted store to %s",
			ABK_FIDO_STORE_PATH);
		kfree(disk);
		return 0;
	}
	pr_warn("abk_fido_key: persist failed path=%s ret=%d reason=%s\n",
		ABK_FIDO_STORE_PATH, ret, reason[0] ? reason : "unknown");

defer_persist:
	kfree(disk);
	abk_fido_dev.store_dirty = false;
	abk_fido_dev.store_generation++;
	if (reason[0]) {
		snprintf(abk_fido_dev.last_error, sizeof(abk_fido_dev.last_error),
			 "%s", reason);
		abk_fido_set_last_trace_locked("persist deferred: %s", reason);
		pr_info("abk_fido_key: persist deferred: %s\n", reason);
	} else {
		abk_fido_set_last_trace_locked("persist deferred: no store path available");
		pr_info("abk_fido_key: persist deferred: no store path available\n");
	}
	return 0;
}

static int abk_fido_reload_store_locked(void)
{
	return abk_fido_restore_persisted_store_locked("reload_store");
}

static int abk_fido_read_store_from_path_locked(const char *path,
						struct abk_fido_store *store,
						char *reason, size_t reason_len)
{
	struct file *file;
	struct abk_fido_store_disk *disk = NULL;
	loff_t pos = 0;
	ssize_t read_ret;
	int ret = 0;
	char validation_reason[96] = "";
	u32 calc_crc;
	u32 legacy_crc;

	file = abk_fido_filp_open_kernel(path, O_RDONLY, 0);
	if (IS_ERR(file)) {
		ret = PTR_ERR(file);
		if (reason && reason_len)
			scnprintf(reason, reason_len, "restore open %s failed: %d",
				  path, ret);
		return ret;
	}

	disk = kzalloc(sizeof(*disk), GFP_KERNEL);
	if (!disk) {
		ret = -ENOMEM;
		if (reason && reason_len)
			scnprintf(reason, reason_len,
				  "restore alloc failed for %s: %d", path, ret);
		goto out;
	}

	read_ret = abk_fido_kernel_read(file, disk, sizeof(*disk), &pos);
	if (read_ret != sizeof(*disk)) {
		ret = read_ret < 0 ? (int)read_ret : -EIO;
		if (reason && reason_len)
			scnprintf(reason, reason_len, "restore read %s failed: %d",
				  path, ret);
		goto out;
	}

	calc_crc = abk_fido_store_crc32(disk);
	legacy_crc = crc32_le(0,
		(u8 *)disk + offsetof(struct abk_fido_store_disk, sign_count),
		sizeof(*disk) - offsetof(struct abk_fido_store_disk, sign_count));
	pr_info("abk_fido_key: read path=%s magic=0x%08x version=%u stored_crc=0x%08x calc_crc=0x%08x legacy_crc=0x%08x sign_count=%u head=%*phN\n",
		path,
		le32_to_cpu(disk->magic),
		le32_to_cpu(disk->version),
		le32_to_cpu(disk->crc32),
		calc_crc,
		legacy_crc,
		le32_to_cpu(disk->sign_count),
		16, disk);

	ret = abk_fido_store_from_disk_into(disk, store, validation_reason,
					    sizeof(validation_reason));
	if (ret) {
		if (reason && reason_len)
			scnprintf(reason, reason_len, "%s (%s)",
				  validation_reason[0] ? validation_reason :
				  "restore validation failed", path);
		goto out;
	}
	ret = 0;

out:
	filp_close(file, NULL);
	kfree(disk);
	return ret;
}

static int abk_fido_restore_persisted_store_locked(const char *source)
{
	struct abk_fido_store *new_store;
	int ret = -ENOENT;
	char reason[96] = "";
	char success_trace[160];

	new_store = kzalloc(sizeof(*new_store), GFP_KERNEL);
	if (!new_store) {
		ret = -ENOMEM;
		snprintf(abk_fido_dev.last_error, sizeof(abk_fido_dev.last_error),
			 "restore alloc failed: %d", ret);
		abk_fido_set_last_trace_locked("%s restore alloc failed", source);
		return ret;
	}

	pr_info("abk_fido_key: restore source=%s trying %s\n",
		source, ABK_FIDO_STORE_PATH);
	ret = abk_fido_read_store_from_path_locked(
		ABK_FIDO_STORE_PATH, new_store, reason, sizeof(reason));
	if (!ret) {
		pr_info("abk_fido_key: restore source=%s succeeded from %s\n",
			source, ABK_FIDO_STORE_PATH);
		memcpy(&abk_fido_dev.store, new_store, sizeof(*new_store));
		abk_fido_dev.store_loaded = true;
		scnprintf(success_trace, sizeof(success_trace),
			  "store restored from %s via %s", ABK_FIDO_STORE_PATH, source);
		abk_fido_finalize_restored_store_locked(success_trace);
		abk_fido_dev.store_generation++;
		kfree(new_store);
		return 0;
	}
	pr_warn("abk_fido_key: restore source=%s failed path=%s ret=%d reason=%s\n",
		source, ABK_FIDO_STORE_PATH, ret, reason[0] ? reason : "unknown");

	snprintf(abk_fido_dev.last_error, sizeof(abk_fido_dev.last_error),
		 "%s", reason[0] ? reason :
		 "no persisted store available");
	abk_fido_set_last_trace_locked("%s restore failed: %s",
		source, reason[0] ? reason :
		"no persisted store available");
	kfree(new_store);
	return ret;
}

static int abk_fido_write_store_to_path_locked(const char *path,
					       const struct abk_fido_store_disk *disk,
					       char *reason, size_t reason_len)
{
	struct file *file;
	loff_t pos = 0;
	ssize_t written;
	int ret;

	file = abk_fido_filp_open_kernel(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (IS_ERR(file)) {
		ret = PTR_ERR(file);
		if (reason && reason_len)
			scnprintf(reason, reason_len, "persist open %s failed: %d",
				  path, ret);
		pr_warn("abk_fido_key: persist open %s failed: %d\n", path, ret);
		return ret;
	}

	written = abk_fido_kernel_write(file, disk, sizeof(*disk), &pos);
	filp_close(file, NULL);
	if (written != sizeof(*disk)) {
		ret = written < 0 ? (int)written : -EIO;
		if (reason && reason_len)
			scnprintf(reason, reason_len, "persist write %s failed: %d",
				  path, ret);
		pr_warn("abk_fido_key: persist write %s failed: %d\n", path, ret);
		return ret;
	}

	return 0;
}

static const char *abk_fido_ctap_name(u8 cmd)
{
	switch (cmd) {
	case ABK_FIDO_CTAP_MAKE_CREDENTIAL:
		return "makeCredential";
	case ABK_FIDO_CTAP_GET_ASSERTION:
		return "getAssertion";
	case ABK_FIDO_CTAP_GET_INFO:
		return "getInfo";
	case ABK_FIDO_CTAP_CLIENT_PIN:
		return "clientPIN";
	case ABK_FIDO_CTAP_RESET:
		return "reset";
	case ABK_FIDO_CTAP_SELECTION:
		return "selection";
	default:
		return "unknown";
	}
}

static int abk_fido_auth_begin_locked(u8 ctap_cmd, const char *rp_id, bool uv, bool rk)
{
	long wait_ret;
	u32 request_id;

	if (!abk_fido_dev.auth_gate_enabled)
		return 0;
	if (abk_fido_dev.auth_cache_valid &&
	    time_before(jiffies, abk_fido_dev.auth_cache_expires)) {
		abk_fido_set_last_trace_locked(
			"auth cache hit cmd=%s rp=%s",
			abk_fido_ctap_name(ctap_cmd), rp_id);
		pr_info("abk_fido_key: auth cache hit cmd=%s rp=%s\n",
			abk_fido_ctap_name(ctap_cmd), rp_id);
		return 0;
	}

	request_id = ++abk_fido_dev.auth_request_id;
	abk_fido_dev.auth_pending = true;
	abk_fido_dev.auth_decided = false;
	abk_fido_dev.auth_allowed = false;
	abk_fido_dev.auth_pending_ctap_cmd = ctap_cmd;
	abk_fido_dev.auth_pending_uv = uv;
	abk_fido_dev.auth_pending_rk = rk;
	strscpy(abk_fido_dev.auth_pending_rp_id, rp_id,
		sizeof(abk_fido_dev.auth_pending_rp_id));
	snprintf(abk_fido_dev.last_error, sizeof(abk_fido_dev.last_error),
		 "awaiting local auth req=%u", request_id);
	abk_fido_set_last_trace_locked(
		"auth pending req=%u cmd=%s rp=%s uv=%u rk=%u",
		request_id, abk_fido_ctap_name(ctap_cmd), rp_id, uv, rk);
	pr_info("abk_fido_key: auth pending req=%u cmd=%s rp=%s uv=%u rk=%u\n",
		request_id, abk_fido_ctap_name(ctap_cmd), rp_id, uv, rk);
	mutex_unlock(&abk_fido_dev.lock);
	abk_fido_bootstrap_companion_service();
	wake_up_interruptible(&abk_fido_dev.auth_wait);
	wait_ret = wait_event_interruptible_timeout(
		abk_fido_dev.auth_wait,
		READ_ONCE(abk_fido_dev.auth_decided),
		msecs_to_jiffies(30000));
	mutex_lock(&abk_fido_dev.lock);

	if (wait_ret < 0) {
		abk_fido_dev.auth_pending = false;
		abk_fido_set_last_trace_locked(
			"auth interrupted req=%u cmd=%s", request_id,
			abk_fido_ctap_name(ctap_cmd));
		pr_warn("abk_fido_key: auth interrupted req=%u cmd=%s ret=%ld\n",
			request_id, abk_fido_ctap_name(ctap_cmd), wait_ret);
		return -EPERM;
	}
	if (!wait_ret) {
		abk_fido_dev.auth_pending = false;
		abk_fido_dev.auth_decided = false;
		abk_fido_set_last_trace_locked(
			"auth timeout req=%u cmd=%s", request_id,
			abk_fido_ctap_name(ctap_cmd));
		snprintf(abk_fido_dev.last_error, sizeof(abk_fido_dev.last_error),
			 "auth timeout req=%u", request_id);
		pr_warn("abk_fido_key: auth timeout req=%u cmd=%s\n",
			request_id, abk_fido_ctap_name(ctap_cmd));
		return -EPERM;
	}
	abk_fido_dev.auth_pending = false;
	abk_fido_dev.auth_decided = false;
	if (!abk_fido_dev.auth_allowed) {
		abk_fido_set_last_trace_locked(
			"auth denied req=%u cmd=%s", request_id,
			abk_fido_ctap_name(ctap_cmd));
		snprintf(abk_fido_dev.last_error, sizeof(abk_fido_dev.last_error),
			 "auth denied req=%u", request_id);
		pr_info("abk_fido_key: auth denied req=%u cmd=%s\n",
			request_id, abk_fido_ctap_name(ctap_cmd));
		return -EPERM;
	}
	abk_fido_set_last_trace_locked(
		"auth allowed req=%u cmd=%s", request_id,
		abk_fido_ctap_name(ctap_cmd));
	abk_fido_dev.auth_cache_valid = true;
	abk_fido_dev.auth_cache_expires = jiffies + msecs_to_jiffies(ABK_FIDO_AUTH_CACHE_MS);
	pr_info("abk_fido_key: auth allowed req=%u cmd=%s\n",
		request_id, abk_fido_ctap_name(ctap_cmd));
	return 0;
}

static int abk_fido_auth_decide_locked(bool allow, u32 request_id, bool check_id)
{
	if (!abk_fido_dev.auth_pending)
		return -ENOENT;
	if (check_id && request_id != abk_fido_dev.auth_request_id)
		return -ESTALE;

	abk_fido_dev.auth_allowed = allow;
	abk_fido_dev.auth_decided = true;
	if (!allow)
		abk_fido_dev.auth_cache_valid = false;
	wake_up_interruptible(&abk_fido_dev.auth_wait);
	return 0;
}

static void abk_fido_authdata_common(const char *rp_id, u8 flags, u32 sign_count,
				     u8 out[37])
{
	u8 hash[SHA256_DIGEST_SIZE];

	abk_fido_sha256((const u8 *)rp_id, strlen(rp_id), hash);
	memcpy(out, hash, SHA256_DIGEST_SIZE);
	out[32] = flags;
	put_unaligned_be32(sign_count, out + 33);
}

static int abk_fido_encode_cose_key(const u8 pub_key[64], s64 alg,
				    u8 *out, size_t *out_len)
{
	struct abk_cbor_writer w;

	abk_cbor_writer_init(&w, out, ABK_FIDO_MAX_CBOR);
	abk_cbor_put_map(&w, 5);
	abk_cbor_put_int(&w, 1);
	abk_cbor_put_int(&w, ABK_FIDO_COSE_KTY_EC2);
	abk_cbor_put_int(&w, 3);
	abk_cbor_put_int(&w, alg);
	abk_cbor_put_int(&w, -1);
	abk_cbor_put_int(&w, ABK_FIDO_COSE_CRV_P256);
	abk_cbor_put_int(&w, -2);
	abk_cbor_put_bytes(&w, pub_key, 32);
	abk_cbor_put_int(&w, -3);
	abk_cbor_put_bytes(&w, pub_key + 32, 32);
	if (w.err)
		return w.err;
	*out_len = w.pos;
	return 0;
}

static int abk_fido_decode_cose_key(struct abk_cbor_reader *r, u8 pub_key[64])
{
	u64 count, i;
	bool have_x = false, have_y = false;

	if (abk_cbor_read_map(r, &count))
		return -EINVAL;

	for (i = 0; i < count; i++) {
		s64 key;
		struct abk_fido_slice slice;

		if (abk_cbor_read_int(r, &key))
			return -EINVAL;
		switch (key) {
		case -2:
			if (abk_cbor_read_bytes(r, &slice) || slice.len != 32)
				return -EINVAL;
			memcpy(pub_key, slice.ptr, 32);
			have_x = true;
			break;
		case -3:
			if (abk_cbor_read_bytes(r, &slice) || slice.len != 32)
				return -EINVAL;
			memcpy(pub_key + 32, slice.ptr, 32);
			have_y = true;
			break;
		default:
			if (abk_cbor_skip(r))
				return -EINVAL;
			break;
		}
	}

	return (have_x && have_y) ? 0 : -EINVAL;
}

static int abk_fido_make_authdata_attested(struct abk_fido_credential *cred,
					   u8 flags, u32 sign_count,
					   u8 *out, size_t *out_len)
{
	u8 cose[128];
	size_t cose_len;
	int ret;

	ret = abk_fido_encode_cose_key(cred->pub_key, ABK_FIDO_COSE_ALG_ES256,
				       cose, &cose_len);
	if (ret)
		return ret;

	abk_fido_authdata_common(cred->rp_id, flags | ABK_FIDO_CRED_FLAG_AT,
				 sign_count, out);
	memcpy(out + 37, abk_fido_dev.store.aaguid, 16);
	put_unaligned_be16(sizeof(cred->cred_id), out + 53);
	memcpy(out + 55, cred->cred_id, sizeof(cred->cred_id));
	memcpy(out + 55 + sizeof(cred->cred_id), cose, cose_len);
	*out_len = 55 + sizeof(cred->cred_id) + cose_len;
	return 0;
}

static int abk_fido_make_authdata_assert(const char *rp_id,
					 u8 flags, u32 sign_count,
					 u8 *out, size_t *out_len)
{
	abk_fido_authdata_common(rp_id, flags, sign_count, out);
	*out_len = 37;
	return 0;
}

static bool abk_fido_is_windows_select_device_make_credential(struct abk_fido_make_cred_req *req)
{
	return !strcmp(req->rp_id, "SelectDevice") &&
	       !strcmp(req->user_name, "SelectDevice");
}

static bool abk_fido_is_webauthn_dummy_make_credential(struct abk_fido_make_cred_req *req)
{
	return !strcmp(req->rp_id, ".dummy") && !strcmp(req->user_name, "dummy");
}

static int abk_fido_encode_dummy_make_credential_cbor(u8 *payload,
						      size_t *payload_len)
{
	struct abk_cbor_writer w;
	u8 auth_data[37] = { 0 };

	abk_cbor_writer_init(&w, payload, ABK_FIDO_MAX_CBOR);
	abk_cbor_put_map(&w, 3);
	/* Match WearAuthn's DUMMY_MAKE_CREDENTIAL_RESPONSE ordering: 2, 1, 3. */
	abk_cbor_put_int(&w, 2);
	abk_cbor_put_bytes(&w, auth_data, sizeof(auth_data));
	abk_cbor_put_int(&w, 1);
	abk_cbor_put_text(&w, "packed");
	abk_cbor_put_int(&w, 3);
	abk_cbor_put_map(&w, 2);
	abk_cbor_put_text(&w, "alg");
	abk_cbor_put_int(&w, ABK_FIDO_COSE_ALG_ES256);
	abk_cbor_put_text(&w, "sig");
	abk_cbor_put_bytes(&w, NULL, 0);
	if (w.err)
		return w.err;

	*payload_len = w.pos;
	return 0;
}

static int abk_fido_make_windows_select_device_resp(struct abk_fido_make_cred_req *req,
						    u8 *payload, size_t *payload_len)
{
	struct abk_cbor_writer w;
	u8 inner_payload[128];
	u8 response_payload[1 + sizeof(inner_payload)];
	u8 zero_aaguid[16] = { 0 };
	size_t inner_payload_len = 0;
	int ret;

	mutex_lock(&abk_fido_dev.lock);
	ret = abk_fido_load_store_locked();
	if (ret && ret != -ENOENT)
		goto out_unlock;

	abk_fido_set_last_trace_locked(
		"windows selectDevice rp=%s user=%s uv=%u",
		req->rp_id, req->user_name, req->uv);
	pr_info("abk_fido_key: windows selectDevice rp=%s user=%s uv=%u\n",
		req->rp_id, req->user_name, req->uv);

	ret = abk_fido_auth_begin_locked(ABK_FIDO_CTAP_MAKE_CREDENTIAL,
					 req->rp_id, req->uv, false);
	if (ret)
		goto out_unlock;

	ret = abk_fido_encode_dummy_make_credential_cbor(inner_payload,
							 &inner_payload_len);
	if (ret)
		goto out_unlock;

	response_payload[0] = ABK_FIDO_CTAP_SUCCESS;
	memcpy(response_payload + 1, inner_payload, inner_payload_len);

	abk_cbor_writer_init(&w, payload, ABK_FIDO_MAX_CBOR);
	abk_cbor_put_map(&w, 3);
	abk_cbor_put_text(&w, "deviceInfo");
	abk_cbor_put_map(&w, 30);
	abk_cbor_put_text(&w, "providerType");
	abk_cbor_put_text(&w, "Hid");
	abk_cbor_put_text(&w, "providerName");
	abk_cbor_put_text(&w, "ABK FIDO");
	abk_cbor_put_text(&w, "devicePath");
	abk_cbor_put_text(&w, "usb:abk-fido");
	abk_cbor_put_text(&w, "manufacturer");
	abk_cbor_put_text(&w, "ABK");
	abk_cbor_put_text(&w, "product");
	abk_cbor_put_text(&w, "ABK FIDO");
	abk_cbor_put_text(&w, "u2fProtocol");
	abk_cbor_put_bool(&w, true);
	abk_cbor_put_text(&w, "u2fAppId");
	abk_cbor_put_bool(&w, true);
	abk_cbor_put_text(&w, "aaGuid");
	abk_cbor_put_bytes(&w, zero_aaguid, sizeof(zero_aaguid));
	abk_cbor_put_text(&w, "pinStatus");
	abk_cbor_put_uint(&w, 1);
	abk_cbor_put_text(&w, "pinRetries");
	abk_cbor_put_uint(&w, abk_fido_dev.store.pin_retries);
	abk_cbor_put_text(&w, "powerCycle");
	abk_cbor_put_bool(&w, false);
	abk_cbor_put_text(&w, "forceChangePin");
	abk_cbor_put_bool(&w, false);
	abk_cbor_put_text(&w, "residentKey");
	abk_cbor_put_bool(&w, false);
	abk_cbor_put_text(&w, "credentialListIndexPlusOne");
	abk_cbor_put_uint(&w, 0);
	abk_cbor_put_text(&w, "credentialId");
	abk_cbor_put_bytes(&w, NULL, 0);
	abk_cbor_put_text(&w, "hmacSecret");
	abk_cbor_put_bytes(&w, NULL, 0);
	abk_cbor_put_text(&w, "credWithHmacSecretArray");
	abk_cbor_put_bytes(&w, NULL, 0);
	abk_cbor_put_text(&w, "uvStatus");
	abk_cbor_put_uint(&w, 0);
	abk_cbor_put_text(&w, "uvRetries");
	abk_cbor_put_uint(&w, 0);
	abk_cbor_put_text(&w, "pinRequiredBeforeSelect");
	abk_cbor_put_bool(&w, false);
	abk_cbor_put_text(&w, "ticket");
	abk_cbor_put_bytes(&w, NULL, 0);
	abk_cbor_put_text(&w, "credLargeBlobStatus");
	abk_cbor_put_uint(&w, 0);
	abk_cbor_put_text(&w, "credLargeBlob");
	abk_cbor_put_bytes(&w, NULL, 0);
	abk_cbor_put_text(&w, "maxMsgSize");
	abk_cbor_put_uint(&w, ABK_FIDO_MAX_MSG);
	abk_cbor_put_text(&w, "maxSerializedLargeBlobArray");
	abk_cbor_put_uint(&w, 0);
	abk_cbor_put_text(&w, "thirdPartyPayment");
	abk_cbor_put_bool(&w, false);
	abk_cbor_put_text(&w, "transports");
	abk_cbor_put_uint(&w, 1);
	abk_cbor_put_text(&w, "clientDataJSON");
	abk_cbor_put_bytes(&w, NULL, 0);
	abk_cbor_put_text(&w, "registrationResponseJSON");
	abk_cbor_put_bytes(&w, NULL, 0);
	abk_cbor_put_text(&w, "authenticationResponseJSON");
	abk_cbor_put_bytes(&w, NULL, 0);
	abk_cbor_put_text(&w, "status");
	abk_cbor_put_uint(&w, 0);
	abk_cbor_put_text(&w, "response");
	abk_cbor_put_bytes(&w, response_payload, inner_payload_len + 1);
	if (w.err) {
		ret = w.err;
		goto out_unlock;
	}

	*payload_len = w.pos;
	pr_info("abk_fido_key: windows selectDevice response len=%zu inner=%zu head=%*phN\n",
		*payload_len,
		inner_payload_len + 1,
		(*payload_len >= 24) ? 24 : (int)*payload_len,
		payload);
	ret = 0;
out_unlock:
	mutex_unlock(&abk_fido_dev.lock);
	return ret;
}

static int abk_fido_make_webauthn_dummy_credential_resp(struct abk_fido_make_cred_req *req,
						       u8 *payload, size_t *payload_len)
{
	int ret;

	mutex_lock(&abk_fido_dev.lock);
	ret = abk_fido_load_store_locked();
	if (ret && ret != -ENOENT)
		goto out_unlock;

	abk_fido_set_last_trace_locked(
		"dummy makeCredential rp=%s user=%s uv=%u",
		req->rp_id, req->user_name, req->uv);
	pr_info("abk_fido_key: dummy makeCredential rp=%s user=%s uv=%u\n",
		req->rp_id, req->user_name, req->uv);

	ret = abk_fido_auth_begin_locked(ABK_FIDO_CTAP_MAKE_CREDENTIAL,
					 req->rp_id, req->uv, false);
	if (ret)
		goto out_unlock;

	ret = abk_fido_encode_dummy_make_credential_cbor(payload, payload_len);
	if (ret)
		goto out_unlock;
	pr_info("abk_fido_key: dummy makeCredential response len=%zu head=%*phN\n",
		*payload_len,
		(*payload_len >= 24) ? 24 : (int)*payload_len,
		payload);
	ret = 0;
out_unlock:
	mutex_unlock(&abk_fido_dev.lock);
	return ret;
}

static bool abk_fido_rp_matches_request(const char *stored_rp, const char *requested_rp)
{
	const char *host;
	size_t host_len;
	const char *slash;

	if (!strcmp(stored_rp, requested_rp))
		return true;

	if (strncmp(requested_rp, "https://", 8))
		return false;

	host = requested_rp + 8;
	slash = strchr(host, '/');
	host_len = slash ? (size_t)(slash - host) : strlen(host);
	if (!host_len)
		return false;

	return strlen(stored_rp) == host_len &&
	       !strncmp(stored_rp, host, host_len);
}

static int abk_fido_credential_matches_allow(struct abk_fido_get_assert_req *req,
					     struct abk_fido_credential *cred)
{
	unsigned int i;

	if (!req->allow_count)
		return 1;

	for (i = 0; i < req->allow_count; i++) {
		if (!req->allow[i].present)
			continue;
		if (req->allow[i].len == sizeof(cred->cred_id) &&
		    !memcmp(req->allow[i].id, cred->cred_id, sizeof(cred->cred_id)))
			return 1;
	}

	pr_info("abk_fido_key: allowlist mismatch rp=%s cred=%*phN allow_count=%u first_allow=%*phN\n",
		cred->rp_id,
		8, cred->cred_id,
		req->allow_count,
		(req->allow_count && req->allow[0].present) ? 8 : 0,
		(req->allow_count && req->allow[0].present) ? req->allow[0].id : cred->cred_id);
	return 0;
}

static int abk_fido_parse_make_cred(const u8 *buf, size_t len,
				    struct abk_fido_make_cred_req *req)
{
	struct abk_cbor_reader r = { .buf = buf, .len = len };
	u64 count, i;

	memset(req, 0, sizeof(*req));
	if (abk_cbor_read_map(&r, &count))
		return -EINVAL;

	for (i = 0; i < count; i++) {
		s64 key;

		if (abk_cbor_read_int(&r, &key))
			return -EINVAL;
		switch (key) {
		case 1: {
			struct abk_fido_slice slice;

			if (abk_cbor_read_bytes(&r, &slice) || slice.len != 32)
				return -EINVAL;
			memcpy(req->client_data_hash, slice.ptr, 32);
			req->have_client_data_hash = true;
			break;
		}
		case 2: {
			u64 rp_count, j;

			if (abk_cbor_read_map(&r, &rp_count))
				return -EINVAL;
			for (j = 0; j < rp_count; j++) {
				struct abk_fido_slice rp_key;
				struct abk_fido_slice text;

				if (abk_cbor_read_text(&r, &rp_key))
					return -EINVAL;
				if (abk_cbor_read_text(&r, &text))
					return -EINVAL;
				if (abk_fido_slice_eq_text(rp_key, "id") &&
				    text.len < ABK_FIDO_MAX_RP_ID) {
					memcpy(req->rp_id, text.ptr, text.len);
					req->rp_id[text.len] = '\0';
					req->have_rp_id = true;
				}
			}
			break;
		}
		case 3: {
			u64 user_count, j;

			if (abk_cbor_read_map(&r, &user_count))
				return -EINVAL;
			for (j = 0; j < user_count; j++) {
				struct abk_fido_slice user_key;

				if (abk_cbor_read_text(&r, &user_key))
					return -EINVAL;
				if (abk_fido_slice_eq_text(user_key, "id")) {
					struct abk_fido_slice slice;

					if (abk_cbor_read_bytes(&r, &slice) ||
					    slice.len > ABK_FIDO_MAX_USER_ID)
						return -EINVAL;
					memcpy(req->user_id, slice.ptr, slice.len);
					req->user_id_len = slice.len;
					req->have_user_id = true;
				} else if (abk_fido_slice_eq_text(user_key, "name") ||
					   abk_fido_slice_eq_text(user_key, "displayName")) {
					struct abk_fido_slice text;
					bool is_name = abk_fido_slice_eq_text(user_key, "name");
					char *dst = is_name ? req->user_name : req->user_display;
					size_t max = is_name ? sizeof(req->user_name) : sizeof(req->user_display);

					if (abk_cbor_read_text(&r, &text) || text.len >= max)
						return -EINVAL;
					memcpy(dst, text.ptr, text.len);
					dst[text.len] = '\0';
				} else {
					if (abk_cbor_skip(&r))
						return -EINVAL;
				}
			}
			break;
		}
		case 4: {
			u64 arr, j;
			bool has_es256 = false;

			if (abk_cbor_read_array(&r, &arr))
				return -EINVAL;
			for (j = 0; j < arr; j++) {
				u64 item_count, k;
				bool type_ok = false;
				bool alg_ok = false;

				if (abk_cbor_read_map(&r, &item_count))
					return -EINVAL;
				for (k = 0; k < item_count; k++) {
					struct abk_fido_slice item_key;

					if (abk_cbor_read_text(&r, &item_key))
						return -EINVAL;
					if (abk_fido_slice_eq_text(item_key, "type")) {
						struct abk_fido_slice text;

						if (abk_cbor_read_text(&r, &text))
							return -EINVAL;
						type_ok = abk_fido_slice_eq_text(text, "public-key");
					} else if (abk_fido_slice_eq_text(item_key, "alg")) {
						s64 alg;

						if (abk_cbor_read_int(&r, &alg))
							return -EINVAL;
						alg_ok = alg == ABK_FIDO_COSE_ALG_ES256;
					} else {
						if (abk_cbor_skip(&r))
							return -EINVAL;
					}
				}
				if (type_ok && alg_ok)
					has_es256 = true;
			}
			if (!has_es256)
				return -EOPNOTSUPP;
			break;
		}
		case 5: {
			u64 arr, j;

			if (abk_cbor_read_array(&r, &arr))
				return -EINVAL;
			for (j = 0; j < arr && req->exclude_count < ARRAY_SIZE(req->exclude); j++) {
				u64 item_count, k;

				if (abk_cbor_read_map(&r, &item_count))
					return -EINVAL;
				for (k = 0; k < item_count; k++) {
					struct abk_fido_slice item_key;

					if (abk_cbor_read_text(&r, &item_key))
						return -EINVAL;
					if (abk_fido_slice_eq_text(item_key, "id")) {
						struct abk_fido_slice slice;

						if (abk_cbor_read_bytes(&r, &slice) ||
						    slice.len > sizeof(req->exclude[req->exclude_count].id))
							return -EINVAL;
						memcpy(req->exclude[req->exclude_count].id,
						       slice.ptr, slice.len);
						req->exclude[req->exclude_count].len = slice.len;
						req->exclude[req->exclude_count].present = true;
					} else {
						if (abk_cbor_skip(&r))
							return -EINVAL;
					}
				}
				req->exclude_count++;
			}
			break;
		}
		case 7: {
			u64 opt_count, j;

			if (abk_cbor_read_map(&r, &opt_count))
				return -EINVAL;
			for (j = 0; j < opt_count; j++) {
				struct abk_fido_slice text;
				bool value;

				if (abk_cbor_read_text(&r, &text) || abk_cbor_read_bool(&r, &value))
					return -EINVAL;
				if (abk_fido_slice_eq_text(text, "rk"))
					req->rk = value;
				else if (abk_fido_slice_eq_text(text, "uv"))
					req->uv = value;
			}
			break;
		}
		case 8: {
			struct abk_fido_slice slice;

			if (abk_cbor_read_bytes(&r, &slice))
				return -EINVAL;
			req->uv = true;
			break;
		}
		case 9: {
			u64 protocol;

			if (abk_cbor_read_uint(&r, &protocol))
				return -EINVAL;
			req->uv = protocol != 0;
			break;
		}
		default:
			if (abk_cbor_skip(&r))
				return -EINVAL;
			break;
		}
	}

	pr_info("abk_fido_key: parsed makeCredential rp=%s user_name=%s user_display=%s user_id_len=%u exclude=%u rk=%u uv=%u\n",
		req->rp_id[0] ? req->rp_id : "<empty>",
		req->user_name[0] ? req->user_name : "<empty>",
		req->user_display[0] ? req->user_display : "<empty>",
		req->user_id_len,
		req->exclude_count,
		req->rk,
		req->uv);
	return (req->have_client_data_hash && req->have_rp_id && req->have_user_id) ? 0 : -EINVAL;
}

static int abk_fido_parse_get_assert(const u8 *buf, size_t len,
				     struct abk_fido_get_assert_req *req)
{
	struct abk_cbor_reader r = { .buf = buf, .len = len };
	u64 count, i;

	memset(req, 0, sizeof(*req));
	if (abk_cbor_read_map(&r, &count))
		return -EINVAL;

	for (i = 0; i < count; i++) {
		s64 key;

		if (abk_cbor_read_int(&r, &key))
			return -EINVAL;
		switch (key) {
		case 1: {
			struct abk_fido_slice text;

			if (abk_cbor_read_text(&r, &text) || text.len >= ABK_FIDO_MAX_RP_ID)
				return -EINVAL;
			memcpy(req->rp_id, text.ptr, text.len);
			req->rp_id[text.len] = '\0';
			req->have_rp_id = true;
			break;
		}
		case 2: {
			struct abk_fido_slice slice;

			if (abk_cbor_read_bytes(&r, &slice) || slice.len != 32)
				return -EINVAL;
			memcpy(req->client_data_hash, slice.ptr, 32);
			req->have_client_data_hash = true;
			break;
		}
		case 3: {
			u64 arr, j;

			if (abk_cbor_read_array(&r, &arr))
				return -EINVAL;
			for (j = 0; j < arr && req->allow_count < ARRAY_SIZE(req->allow); j++) {
				u64 item_count, k;

				if (abk_cbor_read_map(&r, &item_count))
					return -EINVAL;
				for (k = 0; k < item_count; k++) {
					struct abk_fido_slice item_key;

					if (abk_cbor_read_text(&r, &item_key))
						return -EINVAL;
					if (abk_fido_slice_eq_text(item_key, "id")) {
						struct abk_fido_slice slice;

						if (abk_cbor_read_bytes(&r, &slice) ||
						    slice.len > sizeof(req->allow[req->allow_count].id))
							return -EINVAL;
						memcpy(req->allow[req->allow_count].id,
						       slice.ptr, slice.len);
						req->allow[req->allow_count].len = slice.len;
						req->allow[req->allow_count].present = true;
					} else {
						if (abk_cbor_skip(&r))
							return -EINVAL;
					}
				}
				req->allow_count++;
			}
			break;
		}
		case 5: {
			u64 opt_count, j;

			if (abk_cbor_read_map(&r, &opt_count))
				return -EINVAL;
			for (j = 0; j < opt_count; j++) {
				struct abk_fido_slice text;
				bool value;

				if (abk_cbor_read_text(&r, &text) || abk_cbor_read_bool(&r, &value))
					return -EINVAL;
				if (abk_fido_slice_eq_text(text, "uv"))
					req->uv = value;
			}
			break;
		}
		case 6: {
			struct abk_fido_slice slice;

			if (abk_cbor_read_bytes(&r, &slice))
				return -EINVAL;
			req->uv = true;
			break;
		}
		case 7: {
			u64 protocol;

			if (abk_cbor_read_uint(&r, &protocol))
				return -EINVAL;
			req->uv = protocol != 0;
			break;
		}
		default:
			if (abk_cbor_skip(&r))
				return -EINVAL;
			break;
		}
	}

	return (req->have_client_data_hash && req->have_rp_id) ? 0 : -EINVAL;
}

static int abk_fido_parse_client_pin(const u8 *buf, size_t len,
				     struct abk_fido_client_pin_req *req)
{
	struct abk_cbor_reader r = { .buf = buf, .len = len };
	u64 count, i;

	memset(req, 0, sizeof(*req));
	if (abk_cbor_read_map(&r, &count))
		return -EINVAL;

	for (i = 0; i < count; i++) {
		s64 key;

		if (abk_cbor_read_int(&r, &key))
			return -EINVAL;
		switch (key) {
		case 1: {
			u64 protocol;

			if (abk_cbor_read_uint(&r, &protocol))
				return -EINVAL;
			req->protocol = protocol;
			break;
		}
		case 2: {
			u64 subcmd;

			if (abk_cbor_read_uint(&r, &subcmd))
				return -EINVAL;
			req->subcommand = subcmd;
			break;
		}
		case 3:
			if (abk_fido_decode_cose_key(&r, req->key_agreement.pub_key))
				return -EINVAL;
			req->key_agreement.present = true;
			break;
		case 4:
			if (abk_cbor_read_bytes(&r, &req->pin_auth))
				return -EINVAL;
			break;
		case 5:
			if (abk_cbor_read_bytes(&r, &req->new_pin_enc))
				return -EINVAL;
			break;
		case 6:
			if (abk_cbor_read_bytes(&r, &req->pin_hash_enc))
				return -EINVAL;
			break;
		default:
			if (abk_cbor_skip(&r))
				return -EINVAL;
			break;
		}
	}

	return req->subcommand ? 0 : -EINVAL;
}

static int abk_fido_find_credential_by_id_locked(const u8 *cred_id, size_t len)
{
	unsigned int i;

	for (i = 0; i < ABK_FIDO_MAX_CREDS; i++) {
		struct abk_fido_credential *cred = &abk_fido_dev.store.creds[i];

		if (!cred->in_use)
			continue;
		if (len == sizeof(cred->cred_id) &&
		    !memcmp(cred->cred_id, cred_id, sizeof(cred->cred_id)))
			return i;
	}

	return -ENOENT;
}

static int abk_fido_find_rp_credential_locked(struct abk_fido_get_assert_req *req)
{
	unsigned int i;

	for (i = 0; i < ABK_FIDO_MAX_CREDS; i++) {
		struct abk_fido_credential *cred = &abk_fido_dev.store.creds[i];

		if (!cred->in_use)
			continue;
		if (!abk_fido_rp_matches_request(cred->rp_id, req->rp_id)) {
			pr_info("abk_fido_key: candidate slot=%u skip rp stored=%s requested=%s cred=%*phN\n",
				i, cred->rp_id, req->rp_id, 8, cred->cred_id);
			continue;
		}
		if (!abk_fido_credential_matches_allow(req, cred)) {
			pr_info("abk_fido_key: candidate slot=%u rp match but allowlist rejected cred=%*phN\n",
				i, 8, cred->cred_id);
			continue;
		}
		pr_info("abk_fido_key: candidate slot=%u selected rp=%s cred=%*phN\n",
			i, cred->rp_id, 8, cred->cred_id);
		return i;
	}

	pr_info("abk_fido_key: no assertion credential matched rp=%s allow_count=%u\n",
		req->rp_id, req->allow_count);
	return -ENOENT;
}

static int abk_fido_alloc_credential_locked(void)
{
	unsigned int i;

	for (i = 0; i < ABK_FIDO_MAX_CREDS; i++) {
		if (!abk_fido_dev.store.creds[i].in_use)
			return i;
	}
	return -ENOSPC;
}

static noinline_for_stack int abk_fido_make_credential_resp(struct abk_fido_make_cred_req *req,
							     u8 *payload, size_t *payload_len)
{
	struct abk_fido_credential *cred;
	u8 auth_data[512];
	size_t auth_data_len;
	u8 sig[ABK_FIDO_MAX_SIG_DER];
	size_t sig_len;
	u8 to_sign[1024];
	struct abk_cbor_writer w;
	int slot;
	unsigned int i;
	u64 priv_digits[ECC_MAX_DIGITS] = {};
	u64 pub_digits[ECC_MAX_DIGITS * 2] = {};
	int ret;
	u8 flags = ABK_FIDO_CRED_FLAG_UP;
	bool is_windows_select_device = abk_fido_is_windows_select_device_make_credential(req);
	bool is_webauthn_dummy = abk_fido_is_webauthn_dummy_make_credential(req);

	pr_info("abk_fido_key: makeCredential dummy_check rp=%s user=%s windows=%u webauthn=%u\n",
		req->rp_id[0] ? req->rp_id : "<empty>",
		req->user_name[0] ? req->user_name : "<empty>",
		is_windows_select_device,
		is_webauthn_dummy);

	if (is_windows_select_device)
		return abk_fido_make_windows_select_device_resp(req, payload,
								payload_len);
	if (is_webauthn_dummy)
		return abk_fido_make_webauthn_dummy_credential_resp(req, payload,
								    payload_len);

	mutex_lock(&abk_fido_dev.lock);
	ret = abk_fido_load_store_locked();
	if (ret && ret != -ENOENT)
		goto out_unlock;
	abk_fido_set_last_trace_locked(
		"makeCredential rp=%s exclude=%u uv=%u rk=%u pin_set=%u pin_retries=%u",
		req->rp_id, req->exclude_count, req->uv, req->rk,
		abk_fido_pin_configured_locked(), abk_fido_dev.store.pin_retries);
	pr_info("abk_fido_key: makeCredential rp=%s exclude=%u uv=%u rk=%u pin_set=%u pin_retries=%u\n",
		req->rp_id, req->exclude_count, req->uv, req->rk,
		abk_fido_pin_configured_locked(), abk_fido_dev.store.pin_retries);

	ret = abk_fido_auth_begin_locked(ABK_FIDO_CTAP_MAKE_CREDENTIAL,
					 req->rp_id, req->uv, req->rk);
	if (ret)
		goto out_unlock;

	for (i = 0; i < req->exclude_count; i++) {
		if (!req->exclude[i].present)
			continue;
		if (abk_fido_find_credential_by_id_locked(req->exclude[i].id,
							  req->exclude[i].len) >= 0) {
			ret = -EEXIST;
			goto out_unlock;
		}
	}

	slot = abk_fido_alloc_credential_locked();
	if (slot < 0) {
		ret = slot;
		goto out_unlock;
	}

	cred = &abk_fido_dev.store.creds[slot];
	memset(cred, 0, sizeof(*cred));
	cred->in_use = true;
	cred->resident = req->rk;
	get_random_bytes(cred->cred_id, sizeof(cred->cred_id));
	memcpy(cred->user_id, req->user_id, req->user_id_len);
	cred->user_id_len = req->user_id_len;
	strscpy(cred->rp_id, req->rp_id, sizeof(cred->rp_id));
	strscpy(cred->user_name, req->user_name[0] ? req->user_name : "abk-user",
		sizeof(cred->user_name));
	strscpy(cred->user_display,
		req->user_display[0] ? req->user_display : cred->user_name,
		sizeof(cred->user_display));

	ret = ecc_gen_privkey(ECC_CURVE_NIST_P256, ECC_CURVE_NIST_P256_DIGITS,
			      priv_digits);
	if (ret)
		goto revert;
	abk_fido_p256_scalar_to_bytes(priv_digits, cred->priv_key);

	ret = ecc_make_pub_key(ECC_CURVE_NIST_P256, ECC_CURVE_NIST_P256_DIGITS,
			       priv_digits, pub_digits);
	if (ret)
		goto revert;

	abk_fido_p256_pub_to_bytes(pub_digits, cred->pub_key);

	if (req->uv)
		flags |= ABK_FIDO_CRED_FLAG_UV;

	ret = abk_fido_make_authdata_attested(cred, flags,
					      abk_fido_dev.store.sign_count,
					      auth_data, &auth_data_len);
	if (ret)
		goto revert;

	memcpy(to_sign, auth_data, auth_data_len);
	memcpy(to_sign + auth_data_len, req->client_data_hash, 32);
	ret = abk_fido_sha256(to_sign, auth_data_len + 32, to_sign);
	if (ret)
		goto revert;
	ret = abk_fido_ecdsa_sign_p256(cred->priv_key, to_sign, sig, &sig_len);
	if (ret)
		goto revert;

	abk_cbor_writer_init(&w, payload, ABK_FIDO_MAX_CBOR);
	abk_cbor_put_map(&w, 3);
	abk_cbor_put_int(&w, 1);
	abk_cbor_put_text(&w, "packed");
	abk_cbor_put_int(&w, 2);
	abk_cbor_put_bytes(&w, auth_data, auth_data_len);
	abk_cbor_put_int(&w, 3);
	abk_cbor_put_map(&w, 2);
	abk_cbor_put_text(&w, "alg");
	abk_cbor_put_int(&w, ABK_FIDO_COSE_ALG_ES256);
	abk_cbor_put_text(&w, "sig");
	abk_cbor_put_bytes(&w, sig, sig_len);
	if (w.err) {
		ret = w.err;
		goto revert;
	}

	*payload_len = w.pos;
	abk_fido_dev.store_dirty = true;
	ret = abk_fido_maybe_persist_locked();
	mutex_unlock(&abk_fido_dev.lock);
	return ret;

revert:
	memset(cred, 0, sizeof(*cred));
out_unlock:
	mutex_unlock(&abk_fido_dev.lock);
	return ret;
}

static noinline_for_stack int abk_fido_get_assertion_resp(struct abk_fido_get_assert_req *req,
							   u8 *payload, size_t *payload_len)
{
	struct abk_fido_credential *cred;
	u8 auth_data[64];
	size_t auth_data_len;
	u8 sig[ABK_FIDO_MAX_SIG_DER];
	size_t sig_len;
	u8 to_sign[128];
	struct abk_cbor_writer w;
	int slot;
	u32 sign_count;
	int ret;
	u8 flags = ABK_FIDO_CRED_FLAG_UP;
	bool include_user;

	mutex_lock(&abk_fido_dev.lock);
	ret = abk_fido_load_store_locked();
	if (ret)
		goto out_unlock;
	abk_fido_set_last_trace_locked(
		"getAssertion rp=%s allow=%u uv=%u pin_set=%u pin_retries=%u",
		req->rp_id, req->allow_count, req->uv,
		abk_fido_pin_configured_locked(), abk_fido_dev.store.pin_retries);
	pr_info("abk_fido_key: getAssertion rp=%s allow=%u uv=%u pin_set=%u pin_retries=%u\n",
		req->rp_id, req->allow_count, req->uv,
		abk_fido_pin_configured_locked(), abk_fido_dev.store.pin_retries);

	ret = abk_fido_auth_begin_locked(ABK_FIDO_CTAP_GET_ASSERTION,
					 req->rp_id, req->uv, false);
	if (ret)
		goto out_unlock;

	slot = abk_fido_find_rp_credential_locked(req);
	if (slot < 0) {
		ret = slot;
		goto out_unlock;
	}
	cred = &abk_fido_dev.store.creds[slot];
	sign_count = ++abk_fido_dev.store.sign_count;
	if (req->uv)
		flags |= ABK_FIDO_CRED_FLAG_UV;
	include_user = req->allow_count == 0;

	ret = abk_fido_make_authdata_assert(req->rp_id, flags,
					    sign_count, auth_data, &auth_data_len);
	if (ret)
		goto out_unlock;

	memcpy(to_sign, auth_data, auth_data_len);
	memcpy(to_sign + auth_data_len, req->client_data_hash, 32);
	ret = abk_fido_sha256(to_sign, auth_data_len + 32, to_sign);
	if (ret)
		goto out_unlock;
	ret = abk_fido_ecdsa_sign_p256(cred->priv_key, to_sign, sig, &sig_len);
	if (ret)
		goto out_unlock;

	abk_cbor_writer_init(&w, payload, ABK_FIDO_MAX_CBOR);
	abk_cbor_put_map(&w, include_user ? 4 : 3);
	abk_cbor_put_int(&w, 1);
	abk_cbor_put_map(&w, 2);
	abk_cbor_put_text(&w, "id");
	abk_cbor_put_bytes(&w, cred->cred_id, sizeof(cred->cred_id));
	abk_cbor_put_text(&w, "type");
	abk_cbor_put_text(&w, "public-key");
	abk_cbor_put_int(&w, 2);
	abk_cbor_put_bytes(&w, auth_data, auth_data_len);
	abk_cbor_put_int(&w, 3);
	abk_cbor_put_bytes(&w, sig, sig_len);
	if (include_user) {
		abk_cbor_put_int(&w, 4);
		abk_cbor_put_map(&w, 2);
		abk_cbor_put_text(&w, "id");
		abk_cbor_put_bytes(&w, cred->user_id, cred->user_id_len);
		abk_cbor_put_text(&w, "name");
		abk_cbor_put_text(&w, cred->user_name);
	}
	if (w.err) {
		ret = w.err;
		goto out_unlock;
	}

	*payload_len = w.pos;
	abk_fido_dev.store_dirty = true;
	ret = abk_fido_maybe_persist_locked();
out_unlock:
	mutex_unlock(&abk_fido_dev.lock);
	return ret;
}

static noinline_for_stack int abk_fido_get_info_resp(u8 *payload, size_t *payload_len)
{
	struct abk_cbor_writer w;
	int ret;

	mutex_lock(&abk_fido_dev.lock);
	ret = abk_fido_load_store_locked();
	if (ret)
		goto out_unlock;

	abk_cbor_writer_init(&w, payload, ABK_FIDO_MAX_CBOR);
	abk_cbor_put_map(&w, 6);
	abk_cbor_put_int(&w, 1);
	abk_cbor_put_array(&w, 2);
	abk_cbor_put_text(&w, "FIDO_2_0");
	abk_cbor_put_text(&w, "U2F_V2");
	abk_cbor_put_int(&w, 3);
	abk_cbor_put_bytes(&w, abk_fido_dev.store.aaguid, sizeof(abk_fido_dev.store.aaguid));
	abk_cbor_put_int(&w, 4);
	abk_cbor_put_map(&w, 5);
	abk_cbor_put_text(&w, "rk");
	abk_cbor_put_bool(&w, true);
	abk_cbor_put_text(&w, "up");
	abk_cbor_put_bool(&w, true);
	abk_cbor_put_text(&w, "uv");
	abk_cbor_put_bool(&w, abk_fido_dev.auth_gate_enabled);
	abk_cbor_put_text(&w, "plat");
	abk_cbor_put_bool(&w, false);
	abk_cbor_put_text(&w, "clientPin");
	abk_cbor_put_bool(&w, abk_fido_pin_configured_locked());
	abk_cbor_put_int(&w, 5);
	abk_cbor_put_uint(&w, ABK_FIDO_MAX_MSG);
	abk_cbor_put_int(&w, 6);
	abk_cbor_put_array(&w, 1);
	abk_cbor_put_uint(&w, 1);
	abk_cbor_put_int(&w, 8);
	abk_cbor_put_uint(&w, 32);
	if (w.err) {
		ret = w.err;
		goto out_unlock;
	}
	*payload_len = w.pos;
	ret = 0;
out_unlock:
	mutex_unlock(&abk_fido_dev.lock);
	return ret;
}

static void abk_fido_refresh_pin_agreement_locked(void)
{
	u64 priv_digits[ECC_MAX_DIGITS] = {};
	u64 pub_digits[ECC_MAX_DIGITS * 2] = {};

	memset(abk_fido_dev.pin_agreement_priv, 0, sizeof(abk_fido_dev.pin_agreement_priv));
	memset(abk_fido_dev.pin_agreement_pub, 0, sizeof(abk_fido_dev.pin_agreement_pub));
	if (ecc_gen_privkey(ECC_CURVE_NIST_P256, ECC_CURVE_NIST_P256_DIGITS,
			    priv_digits))
		return;
	abk_fido_p256_scalar_to_bytes(priv_digits, abk_fido_dev.pin_agreement_priv);
	if (ecc_make_pub_key(ECC_CURVE_NIST_P256, ECC_CURVE_NIST_P256_DIGITS,
			     priv_digits, pub_digits))
		return;
	abk_fido_p256_pub_to_bytes(pub_digits, abk_fido_dev.pin_agreement_pub);
	abk_fido_dev.pin_agreement_valid = true;
}

static int abk_fido_shared_secret_locked(const u8 peer_pub[64], u8 shared_key[32])
{
	u64 priv[ECC_MAX_DIGITS] = {};
	u64 pub[ECC_MAX_DIGITS * 2] = {};
	u64 secret[ECC_MAX_DIGITS] = {};
	int ret;

	if (!abk_fido_dev.pin_agreement_valid)
		abk_fido_refresh_pin_agreement_locked();
	if (!abk_fido_dev.pin_agreement_valid)
		return -EKEYREJECTED;

	abk_fido_p256_scalar_from_bytes(abk_fido_dev.pin_agreement_priv, priv);
	abk_fido_p256_pub_from_bytes(peer_pub, pub);
	ret = crypto_ecdh_shared_secret(ECC_CURVE_NIST_P256,
					ECC_CURVE_NIST_P256_DIGITS,
					priv, pub, secret);
	if (ret)
		return ret;

	return abk_fido_sha256((const u8 *)secret,
			       ECC_CURVE_NIST_P256_DIGITS * sizeof(u64),
			       shared_key);
}

static noinline_for_stack int abk_fido_client_pin_resp(const u8 *buf, size_t len,
						       u8 *payload, size_t *payload_len)
{
	struct abk_fido_client_pin_req req;
	struct abk_cbor_writer w;
	u8 shared_key[32];
	u8 work[80];
	int ret = 0;

	ret = abk_fido_parse_client_pin(buf, len, &req);
	if (ret)
		return -EINVAL;
	if (req.protocol && req.protocol != 1)
		return -EINVAL;

	mutex_lock(&abk_fido_dev.lock);
	ret = abk_fido_load_store_locked();
	if (ret)
		goto out_unlock;

	abk_cbor_writer_init(&w, payload, ABK_FIDO_MAX_CBOR);
	abk_fido_set_last_trace_locked(
		"clientPIN subcmd=%u pin_set=%u pin_retries=%u key_agreement=%u",
		req.subcommand, abk_fido_pin_configured_locked(),
		abk_fido_dev.store.pin_retries, req.key_agreement.present);
	pr_info("abk_fido_key: clientPIN subcmd=%u pin_set=%u pin_retries=%u key_agreement=%u\n",
		req.subcommand, abk_fido_pin_configured_locked(),
		abk_fido_dev.store.pin_retries, req.key_agreement.present);

	switch (req.subcommand) {
	case ABK_FIDO_CLIENT_PIN_GET_RETRIES:
		abk_cbor_put_map(&w, 1);
		abk_cbor_put_int(&w, 3);
		abk_cbor_put_uint(&w, abk_fido_dev.store.pin_retries);
		break;
	case ABK_FIDO_CLIENT_PIN_GET_KEY_AGREEMENT:
	{
		size_t cose_len = 0;

		if (!abk_fido_dev.pin_agreement_valid)
			abk_fido_refresh_pin_agreement_locked();
		abk_cbor_put_map(&w, 1);
		abk_cbor_put_int(&w, 1);
		ret = abk_fido_encode_cose_key(abk_fido_dev.pin_agreement_pub,
					       ABK_FIDO_COSE_ALG_ECDH_ES_HKDF_256,
					       payload + w.pos, &cose_len);
		if (ret)
			goto out_unlock;
		w.pos += cose_len;
		break;
	}
	case ABK_FIDO_CLIENT_PIN_SET_PIN:
		if (abk_fido_pin_configured_locked()) {
			ret = -EALREADY;
			goto out_unlock;
		}
		if (!req.key_agreement.present || !req.new_pin_enc.len) {
			ret = -EINVAL;
			goto out_unlock;
		}
		memset(abk_fido_dev.store.pin_hash, 0, sizeof(abk_fido_dev.store.pin_hash));
		get_random_bytes(abk_fido_dev.store.pin_token,
				 sizeof(abk_fido_dev.store.pin_token));
		abk_fido_dev.store.pin_set = true;
		abk_fido_dev.store.pin_retries = ABK_FIDO_PIN_RETRIES_DEFAULT;
		abk_fido_dev.store_dirty = true;
		ret = abk_fido_maybe_persist_locked();
		break;
	case ABK_FIDO_CLIENT_PIN_GET_PIN_TOKEN:
		if (!abk_fido_pin_configured_locked()) {
			ret = -ENOENT;
			goto out_unlock;
		}
		if (!req.key_agreement.present) {
			ret = -EINVAL;
			goto out_unlock;
		}
		if (!abk_fido_dev.store.pin_retries) {
			ret = -EACCES;
			goto out_unlock;
		}
		ret = abk_fido_shared_secret_locked(req.key_agreement.pub_key, shared_key);
		if (ret)
			goto out_unlock;
		abk_fido_dev.store.pin_retries = ABK_FIDO_PIN_RETRIES_DEFAULT;
		memcpy(work, abk_fido_dev.store.pin_token,
		       sizeof(abk_fido_dev.store.pin_token));
		ret = abk_fido_aes256_cbc(true, shared_key, work,
					  sizeof(abk_fido_dev.store.pin_token));
		if (ret)
			goto out_unlock;
		abk_cbor_put_map(&w, 1);
		abk_cbor_put_int(&w, 2);
		abk_cbor_put_bytes(&w, work, sizeof(abk_fido_dev.store.pin_token));
		break;
	case ABK_FIDO_CLIENT_PIN_CHANGE_PIN:
		if (!abk_fido_pin_configured_locked()) {
			ret = -ENOENT;
			goto out_unlock;
		}
		if (!req.key_agreement.present || !req.new_pin_enc.len) {
			ret = -EINVAL;
			goto out_unlock;
		}
		get_random_bytes(abk_fido_dev.store.pin_token,
				 sizeof(abk_fido_dev.store.pin_token));
		abk_fido_dev.store.pin_retries = ABK_FIDO_PIN_RETRIES_DEFAULT;
		abk_fido_dev.store_dirty = true;
		ret = abk_fido_maybe_persist_locked();
		break;
	default:
		ret = -EOPNOTSUPP;
		break;
	}

	if (w.err && !ret)
		ret = w.err;
	if (ret) {
		abk_fido_set_last_trace_locked(
			"clientPIN failed subcmd=%u ret=%d pin_set=%u pin_retries=%u",
			req.subcommand, ret, abk_fido_pin_configured_locked(),
			abk_fido_dev.store.pin_retries);
		pr_warn("abk_fido_key: clientPIN failed subcmd=%u ret=%d pin_set=%u pin_retries=%u\n",
			req.subcommand, ret, abk_fido_pin_configured_locked(),
			abk_fido_dev.store.pin_retries);
	}
	if (!ret)
		*payload_len = w.pos;
out_unlock:
	mutex_unlock(&abk_fido_dev.lock);
	return ret;
}

static noinline_for_stack int abk_fido_cbor_dispatch(const u8 *msg, size_t len,
						      u8 *payload, size_t *payload_len)
{
	u8 cmd;
	int ret;

	if (!len)
		return -EINVAL;

	cmd = msg[0];
	switch (cmd) {
	case ABK_FIDO_CTAP_GET_INFO:
		return abk_fido_get_info_resp(payload, payload_len);
	case ABK_FIDO_CTAP_MAKE_CREDENTIAL: {
		struct abk_fido_make_cred_req *req;

		req = kzalloc(sizeof(*req), GFP_KERNEL);
		if (!req)
			return -ENOMEM;

		ret = abk_fido_parse_make_cred(msg + 1, len - 1, req);
		if (!ret)
			ret = abk_fido_make_credential_resp(req, payload, payload_len);
		kfree(req);
		return ret ? (ret == -EOPNOTSUPP ? ret : ret) : 0;
	}
	case ABK_FIDO_CTAP_GET_ASSERTION: {
		struct abk_fido_get_assert_req *req;

		req = kzalloc(sizeof(*req), GFP_KERNEL);
		if (!req)
			return -ENOMEM;
		ret = abk_fido_parse_get_assert(msg + 1, len - 1, req);
		if (!ret)
			ret = abk_fido_get_assertion_resp(req, payload, payload_len);
		kfree(req);
		return ret ? ret : 0;
	}
	case ABK_FIDO_CTAP_RESET:
		mutex_lock(&abk_fido_dev.lock);
		memset(&abk_fido_dev.store, 0, sizeof(abk_fido_dev.store));
		abk_fido_dev.store.pin_retries = ABK_FIDO_PIN_RETRIES_DEFAULT;
		get_random_bytes(abk_fido_dev.store.aaguid,
				 sizeof(abk_fido_dev.store.aaguid));
		get_random_bytes(abk_fido_dev.store.pin_token,
				 sizeof(abk_fido_dev.store.pin_token));
		abk_fido_dev.store_dirty = true;
		ret = abk_fido_maybe_persist_locked();
		mutex_unlock(&abk_fido_dev.lock);
		return ret;
	case ABK_FIDO_CTAP_SELECTION:
		*payload_len = 0;
		return 0;
	case ABK_FIDO_CTAP_CLIENT_PIN:
		return abk_fido_client_pin_resp(msg + 1, len - 1, payload, payload_len);
	default:
		return -ENOIOCTLCMD;
	}
}

static struct abk_fido_channel *abk_fido_find_channel_locked(u32 cid)
{
	unsigned int i;

	for (i = 0; i < ABK_FIDO_MAX_CHANNELS; i++) {
		if (abk_fido_dev.channels[i].in_use &&
		    abk_fido_dev.channels[i].cid == cid)
			return &abk_fido_dev.channels[i];
	}
	return NULL;
}

static struct abk_fido_channel *abk_fido_alloc_channel_locked(u32 cid)
{
	unsigned int i;

	for (i = 0; i < ABK_FIDO_MAX_CHANNELS; i++) {
		if (!abk_fido_dev.channels[i].in_use) {
			memset(&abk_fido_dev.channels[i], 0,
			       sizeof(abk_fido_dev.channels[i]));
			abk_fido_dev.channels[i].in_use = true;
			abk_fido_dev.channels[i].cid = cid;
			return &abk_fido_dev.channels[i];
		}
	}
	return &abk_fido_dev.channels[0];
}

static u32 abk_fido_next_cid_locked(void)
{
	u32 cid = abk_fido_dev.next_cid++;

	if (!cid || cid == ABK_FIDO_CID_BROADCAST)
		cid = ++abk_fido_dev.next_cid;
	return cid;
}

static void abk_fido_tx_kick(struct abk_fido_usb *usb);

static void abk_fido_send_hid_message(struct abk_fido_usb *usb, u32 cid, u8 cmd,
				      const u8 *payload, size_t len)
{
	u8 packet[ABK_FIDO_REPORT_LEN];
	size_t offset = 0;
	u8 seq = 0;
	size_t chunk;

	if (!usb)
		usb = &abk_fido_user_usb;

	memset(packet, 0, sizeof(packet));
	put_unaligned_be32(cid, packet);
	packet[4] = cmd | 0x80;
	put_unaligned_be16(len, packet + 5);
	chunk = min_t(size_t, len, ABK_FIDO_REPORT_LEN - 7);
	if (chunk)
		memcpy(packet + 7, payload, chunk);
	abk_fido_queue_push(&usb->tx_packets, packet, sizeof(packet));
	offset += chunk;

	while (offset < len) {
		memset(packet, 0, sizeof(packet));
		put_unaligned_be32(cid, packet);
		packet[4] = seq++;
		chunk = min_t(size_t, len - offset, ABK_FIDO_REPORT_LEN - 5);
		memcpy(packet + 5, payload + offset, chunk);
		abk_fido_queue_push(&usb->tx_packets, packet, sizeof(packet));
		offset += chunk;
	}

	if (usb->userspace)
		wake_up_interruptible(&usb->tx_packets.wait);
	else
		abk_fido_tx_kick(usb);
}

static void abk_fido_send_hid_error(struct abk_fido_usb *usb, u32 cid, u8 err)
{
	abk_fido_send_hid_message(usb, cid, ABK_FIDO_HID_ERROR, &err, 1);
}

static void abk_fido_send_cbor_result(struct abk_fido_usb *usb, u32 cid,
				      u8 status, const u8 *payload, size_t payload_len)
{
	u8 *buf;

	buf = kmalloc(payload_len + 1, GFP_KERNEL);
	if (!buf) {
		abk_fido_send_hid_error(usb, cid, ABK_FIDO_HID_ERR_OTHER);
		return;
	}
	buf[0] = status;
	if (payload_len)
		memcpy(buf + 1, payload, payload_len);
	abk_fido_send_hid_message(usb, cid, ABK_FIDO_HID_CBOR, buf, payload_len + 1);
	kfree(buf);
}

static void abk_fido_dispatch_msg(struct abk_fido_usb *usb, u32 cid, u8 cmd,
				  const u8 *data, size_t len)
{
	u8 payload[ABK_FIDO_MAX_CBOR];
	size_t payload_len = 0;
	u8 init_resp[17];
	u8 cbor_cmd = len ? data[0] : 0;
	u32 new_cid;
	int ret;

	switch (cmd) {
	case ABK_FIDO_HID_INIT:
		if (len < 8) {
			abk_fido_send_hid_error(usb, cid, ABK_FIDO_HID_ERR_INVALID_LEN);
			return;
		}
		mutex_lock(&abk_fido_dev.lock);
		new_cid = abk_fido_next_cid_locked();
		abk_fido_alloc_channel_locked(new_cid);
		mutex_unlock(&abk_fido_dev.lock);
		memcpy(init_resp, data, 8);
		put_unaligned_be32(new_cid, init_resp + 8);
		init_resp[12] = 2;
		init_resp[13] = 0;
		init_resp[14] = 1;
		init_resp[15] = 0;
		init_resp[16] = 0x0d;
		abk_fido_send_hid_message(usb, cid, ABK_FIDO_HID_INIT,
					  init_resp, sizeof(init_resp));
		return;
	case ABK_FIDO_HID_PING:
		abk_fido_send_hid_message(usb, cid, ABK_FIDO_HID_PING, data, len);
		return;
	case ABK_FIDO_HID_WINK:
		abk_fido_send_hid_message(usb, cid, ABK_FIDO_HID_WINK, NULL, 0);
		return;
	case ABK_FIDO_HID_CANCEL:
		mutex_lock(&abk_fido_dev.lock);
		if (abk_fido_find_channel_locked(cid))
			abk_fido_find_channel_locked(cid)->cancelled = true;
		mutex_unlock(&abk_fido_dev.lock);
		return;
	case ABK_FIDO_HID_CBOR:
		ret = abk_fido_cbor_dispatch(data, len, payload, &payload_len);
		if (!ret) {
			mutex_lock(&abk_fido_dev.lock);
			abk_fido_dev.last_error[0] = '\0';
			mutex_unlock(&abk_fido_dev.lock);
			abk_fido_send_cbor_result(usb, cid, ABK_FIDO_CTAP_SUCCESS,
						  payload, payload_len);
		} else if (ret == -EEXIST)
			abk_fido_send_cbor_result(usb, cid,
						  ABK_FIDO_CTAP_ERR_CREDENTIAL_EXCLUDED,
						  NULL, 0);
		else if (ret == -ENOSPC)
			abk_fido_send_cbor_result(usb, cid,
						  ABK_FIDO_CTAP_ERR_KEY_STORE_FULL,
						  NULL, 0);
		else if (ret == -ENOENT)
			abk_fido_send_cbor_result(usb, cid,
						  ABK_FIDO_CTAP_ERR_NO_CREDENTIALS,
						  NULL, 0);
		else if (ret == -EOPNOTSUPP || ret == -ENOIOCTLCMD)
			abk_fido_send_cbor_result(usb, cid,
						  ABK_FIDO_CTAP_ERR_UNSUPPORTED_OPTION,
						  NULL, 0);
		else if (ret == -EALREADY)
			abk_fido_send_cbor_result(usb, cid,
						  ABK_FIDO_CTAP_ERR_OPERATION_DENIED,
						  NULL, 0);
		else if (ret == -EPERM || ret == -ETIMEDOUT)
			abk_fido_send_cbor_result(usb, cid,
						  ABK_FIDO_CTAP_ERR_OPERATION_DENIED,
						  NULL, 0);
		else if (ret == -EACCES)
			abk_fido_send_cbor_result(usb, cid,
						  ABK_FIDO_CTAP_ERR_PIN_BLOCKED,
						  NULL, 0);
		else if (ret == -EKEYREJECTED)
			abk_fido_send_cbor_result(usb, cid,
						  ABK_FIDO_CTAP_ERR_PIN_AUTH_INVALID,
						  NULL, 0);
		else
			abk_fido_send_cbor_result(usb, cid,
						  ABK_FIDO_CTAP_ERR_INVALID_PARAMETER,
						  NULL, 0);
		if (ret) {
			mutex_lock(&abk_fido_dev.lock);
			snprintf(abk_fido_dev.last_error, sizeof(abk_fido_dev.last_error),
				 "ctap cmd 0x%02x failed: %d", cbor_cmd, ret);
			mutex_unlock(&abk_fido_dev.lock);
			pr_warn("abk_fido_key: ctap cmd 0x%02x failed: %d\n",
				cbor_cmd, ret);
		}
		return;
	default:
		abk_fido_send_hid_error(usb, cid, ABK_FIDO_HID_ERR_INVALID_CMD);
		return;
	}
}

static void abk_fido_process_packet(struct abk_fido_usb *usb, const u8 *packet, size_t len)
{
	struct abk_fido_channel *ch;
	u32 cid;
	u8 header;
	size_t chunk;
	u8 *msg = NULL;
	size_t msg_len = 0;
	u8 cmd = 0;

	if (len != ABK_FIDO_REPORT_LEN)
		return;

	cid = get_unaligned_be32(packet);
	header = packet[4];

	mutex_lock(&abk_fido_dev.lock);
	if (header & 0x80) {
		u16 expected = get_unaligned_be16(packet + 5);

		if (expected > ABK_FIDO_MAX_MSG) {
			mutex_unlock(&abk_fido_dev.lock);
			abk_fido_send_hid_error(usb, cid, ABK_FIDO_HID_ERR_INVALID_LEN);
			return;
		}
		ch = abk_fido_find_channel_locked(cid);
		if (!ch)
			ch = abk_fido_alloc_channel_locked(cid);
		memset(ch, 0, sizeof(*ch));
		ch->in_use = true;
		ch->cid = cid;
		ch->cmd = header & 0x7f;
		ch->expected_len = expected;
		ch->received_len = min_t(size_t, expected, ABK_FIDO_REPORT_LEN - 7);
		ch->next_seq = 0;
		memcpy(ch->msg, packet + 7, ch->received_len);
		if (ch->received_len == ch->expected_len) {
			cmd = ch->cmd;
			msg_len = ch->received_len;
			msg = kmemdup(ch->msg, msg_len, GFP_KERNEL);
			memset(ch, 0, sizeof(*ch));
			mutex_unlock(&abk_fido_dev.lock);
			if (msg) {
				abk_fido_dispatch_msg(usb, cid, cmd, msg, msg_len);
				kfree(msg);
			} else {
				abk_fido_send_hid_error(usb, cid, ABK_FIDO_HID_ERR_OTHER);
			}
			return;
		}
		mutex_unlock(&abk_fido_dev.lock);
		return;
	}

	ch = abk_fido_find_channel_locked(cid);
	if (!ch || !ch->in_use) {
		mutex_unlock(&abk_fido_dev.lock);
		abk_fido_send_hid_error(usb, cid, ABK_FIDO_HID_ERR_INVALID_CID);
		return;
	}
	if (header != ch->next_seq) {
		memset(ch, 0, sizeof(*ch));
		mutex_unlock(&abk_fido_dev.lock);
		abk_fido_send_hid_error(usb, cid, ABK_FIDO_HID_ERR_INVALID_SEQ);
		return;
	}

	ch->next_seq++;
	chunk = min_t(size_t, ch->expected_len - ch->received_len, ABK_FIDO_REPORT_LEN - 5);
	memcpy(ch->msg + ch->received_len, packet + 5, chunk);
	ch->received_len += chunk;
	if (ch->received_len == ch->expected_len) {
		cmd = ch->cmd;
		msg_len = ch->received_len;
		msg = kmemdup(ch->msg, msg_len, GFP_KERNEL);
		memset(ch, 0, sizeof(*ch));
		mutex_unlock(&abk_fido_dev.lock);
		if (msg) {
			abk_fido_dispatch_msg(usb, cid, cmd, msg, msg_len);
			kfree(msg);
		} else {
			abk_fido_send_hid_error(usb, cid, ABK_FIDO_HID_ERR_OTHER);
		}
		return;
	}
	mutex_unlock(&abk_fido_dev.lock);
}

static void abk_fido_rx_worker(struct work_struct *work)
{
	struct abk_fido_usb *usb = container_of(work, struct abk_fido_usb, rx_work);
	struct abk_fido_report report;

	while (abk_fido_queue_pop(&usb->rx_packets, &report))
		abk_fido_process_packet(usb, report.data, report.len);
}

static void abk_fido_tx_complete(struct usb_ep *ep, struct usb_request *req)
{
	struct abk_fido_usb *usb = req->context;
	unsigned long flags;

	spin_lock_irqsave(&usb->tx_lock, flags);
	usb->tx_pending = false;
	spin_unlock_irqrestore(&usb->tx_lock, flags);
	abk_fido_tx_kick(usb);
}

static void abk_fido_tx_kick(struct abk_fido_usb *usb)
{
	struct abk_fido_report report;
	unsigned long flags;
	int ret;

	if (!usb->online || !usb->in_req)
		return;
	if (!abk_fido_queue_pop(&usb->tx_packets, &report))
		return;

	spin_lock_irqsave(&usb->tx_lock, flags);
	if (usb->tx_pending) {
		spin_unlock_irqrestore(&usb->tx_lock, flags);
		abk_fido_queue_push(&usb->tx_packets, report.data, report.len);
		return;
	}
	usb->tx_pending = true;
	spin_unlock_irqrestore(&usb->tx_lock, flags);

	memset(usb->in_req->buf, 0, ABK_FIDO_REPORT_LEN);
	memcpy(usb->in_req->buf, report.data, report.len);
	usb->in_req->length = ABK_FIDO_REPORT_LEN;
	ret = usb_ep_queue(usb->in_ep, usb->in_req, GFP_ATOMIC);
	if (ret) {
		spin_lock_irqsave(&usb->tx_lock, flags);
		usb->tx_pending = false;
		spin_unlock_irqrestore(&usb->tx_lock, flags);
	}
}

static void abk_fido_out_complete(struct usb_ep *ep, struct usb_request *req)
{
	struct abk_fido_usb *usb = req->context;
	int ret;

	if (req->status == 0 && req->actual == ABK_FIDO_REPORT_LEN) {
		abk_fido_queue_push(&usb->debug_rx, req->buf, req->actual);
		abk_fido_queue_push(&usb->rx_packets, req->buf, req->actual);
		schedule_work(&usb->rx_work);
	}

	req->actual = 0;
	req->length = ABK_FIDO_REPORT_LEN;
	ret = usb_ep_queue(ep, req, GFP_ATOMIC);
	if (ret)
		pr_warn("abk_fido_key: failed to requeue out request: %d\n", ret);
}

static ssize_t abk_fido_misc_read(struct file *file, char __user *buf,
				  size_t count, loff_t *ppos)
{
	struct miscdevice *misc = file->private_data;
	struct abk_fido_usb *usb = container_of(misc, struct abk_fido_usb, miscdev);
	struct abk_fido_report report;

	if (count < ABK_FIDO_REPORT_LEN)
		return -EINVAL;
	if (!abk_fido_queue_pop(&usb->debug_rx, &report)) {
		if (file->f_flags & O_NONBLOCK)
			return -EAGAIN;
		if (wait_event_interruptible(usb->debug_rx.wait,
					     !abk_fido_queue_empty(&usb->debug_rx)))
			return -ERESTARTSYS;
		if (!abk_fido_queue_pop(&usb->debug_rx, &report))
			return -EAGAIN;
	}
	if (copy_to_user(buf, report.data, report.len))
		return -EFAULT;
	return report.len;
}

static ssize_t abk_fido_misc_write(struct file *file, const char __user *buf,
				   size_t count, loff_t *ppos)
{
	struct miscdevice *misc = file->private_data;
	struct abk_fido_usb *usb = container_of(misc, struct abk_fido_usb, miscdev);
	u8 packet[ABK_FIDO_REPORT_LEN];

	if (count != ABK_FIDO_REPORT_LEN)
		return -EINVAL;
	if (copy_from_user(packet, buf, count))
		return -EFAULT;
	if (!abk_fido_queue_push(&usb->tx_packets, packet, count))
		return -EBUSY;
	abk_fido_tx_kick(usb);
	return count;
}

static __poll_t abk_fido_misc_poll(struct file *file, poll_table *wait)
{
	struct miscdevice *misc = file->private_data;
	struct abk_fido_usb *usb = container_of(misc, struct abk_fido_usb, miscdev);
	__poll_t mask = EPOLLOUT | EPOLLWRNORM;

	poll_wait(file, &usb->debug_rx.wait, wait);
	if (!abk_fido_queue_empty(&usb->debug_rx))
		mask |= EPOLLIN | EPOLLRDNORM;
	return mask;
}

static const struct file_operations abk_fido_misc_fops = {
	.owner = THIS_MODULE,
	.read = abk_fido_misc_read,
	.write = abk_fido_misc_write,
	.poll = abk_fido_misc_poll,
	.llseek = no_llseek,
};

static ssize_t abk_fido_user_read(struct file *file, char __user *buf,
				  size_t count, loff_t *ppos)
{
	struct miscdevice *misc = file->private_data;
	struct abk_fido_usb *usb = container_of(misc, struct abk_fido_usb, miscdev);
	struct abk_fido_report report;

	if (count < ABK_FIDO_REPORT_LEN)
		return -EINVAL;
	if (!abk_fido_queue_pop(&usb->tx_packets, &report)) {
		if (file->f_flags & O_NONBLOCK)
			return -EAGAIN;
		if (wait_event_interruptible(usb->tx_packets.wait,
					     !abk_fido_queue_empty(&usb->tx_packets)))
			return -ERESTARTSYS;
		if (!abk_fido_queue_pop(&usb->tx_packets, &report))
			return -EAGAIN;
	}
	if (copy_to_user(buf, report.data, report.len))
		return -EFAULT;
	return report.len;
}

static ssize_t abk_fido_user_write(struct file *file, const char __user *buf,
				   size_t count, loff_t *ppos)
{
	struct miscdevice *misc = file->private_data;
	struct abk_fido_usb *usb = container_of(misc, struct abk_fido_usb, miscdev);
	u8 packet[ABK_FIDO_REPORT_LEN];

	if (count != ABK_FIDO_REPORT_LEN)
		return -EINVAL;
	if (copy_from_user(packet, buf, count))
		return -EFAULT;
	if (!abk_fido_queue_push(&usb->rx_packets, packet, count))
		return -EBUSY;
	schedule_work(&usb->rx_work);
	return count;
}

static __poll_t abk_fido_user_poll(struct file *file, poll_table *wait)
{
	struct miscdevice *misc = file->private_data;
	struct abk_fido_usb *usb = container_of(misc, struct abk_fido_usb, miscdev);
	__poll_t mask = EPOLLOUT | EPOLLWRNORM;

	poll_wait(file, &usb->tx_packets.wait, wait);
	if (!abk_fido_queue_empty(&usb->tx_packets))
		mask |= EPOLLIN | EPOLLRDNORM;
	return mask;
}

static const struct file_operations abk_fido_user_fops = {
	.owner = THIS_MODULE,
	.read = abk_fido_user_read,
	.write = abk_fido_user_write,
	.poll = abk_fido_user_poll,
	.llseek = no_llseek,
};

static int abk_fido_setup(struct usb_function *f,
			  const struct usb_ctrlrequest *ctrl)
{
	struct abk_fido_usb *usb = container_of(f, struct abk_fido_usb, func);
	struct usb_composite_dev *cdev = f->config->cdev;
	struct usb_request *req = cdev->req;
	u16 w_value = le16_to_cpu(ctrl->wValue);
	u16 w_length = le16_to_cpu(ctrl->wLength);
	int value = -EOPNOTSUPP;

	switch ((ctrl->bRequestType << 8) | ctrl->bRequest) {
	case ((USB_DIR_IN | USB_TYPE_STANDARD | USB_RECIP_INTERFACE) << 8) |
	     USB_REQ_GET_DESCRIPTOR:
		if ((w_value >> 8) == HID_DT_HID) {
			struct hid_descriptor desc = abk_fido_hid_desc;

			desc.desc[0].bDescriptorType = HID_DT_REPORT;
			desc.desc[0].wDescriptorLength =
				cpu_to_le16(ABK_FIDO_REPORT_DESC_LEN);
			value = min_t(unsigned int, w_length, desc.bLength);
			memcpy(req->buf, &desc, value);
		} else if ((w_value >> 8) == HID_DT_REPORT) {
			value = min_t(unsigned int, w_length, ABK_FIDO_REPORT_DESC_LEN);
			memcpy(req->buf, abk_fido_report_desc, value);
		}
		break;
	case ((USB_DIR_IN | USB_TYPE_CLASS | USB_RECIP_INTERFACE) << 8) |
	     HID_REQ_GET_PROTOCOL:
		((u8 *)req->buf)[0] = usb->protocol;
		value = min_t(unsigned int, w_length, 1);
		break;
	case ((USB_DIR_OUT | USB_TYPE_CLASS | USB_RECIP_INTERFACE) << 8) |
	     HID_REQ_SET_PROTOCOL:
		usb->protocol = w_value;
		value = 0;
		break;
	case ((USB_DIR_IN | USB_TYPE_CLASS | USB_RECIP_INTERFACE) << 8) |
	     HID_REQ_GET_IDLE:
		((u8 *)req->buf)[0] = usb->idle;
		value = min_t(unsigned int, w_length, 1);
		break;
	case ((USB_DIR_OUT | USB_TYPE_CLASS | USB_RECIP_INTERFACE) << 8) |
	     HID_REQ_SET_IDLE:
		usb->idle = w_value >> 8;
		value = 0;
		break;
	default:
		break;
	}

	if (value >= 0) {
		req->zero = 0;
		req->length = value;
		return usb_ep_queue(cdev->gadget->ep0, req, GFP_ATOMIC);
	}

	return value;
}

static void abk_fido_disable(struct usb_function *f)
{
	struct abk_fido_usb *usb = container_of(f, struct abk_fido_usb, func);
	unsigned int i;
	unsigned long flags;

	if (usb->in_ep)
		usb_ep_disable(usb->in_ep);
	if (usb->out_ep)
		usb_ep_disable(usb->out_ep);

	spin_lock_irqsave(&usb->tx_lock, flags);
	usb->tx_pending = false;
	usb->online = false;
	spin_unlock_irqrestore(&usb->tx_lock, flags);

	if (usb->in_req) {
		free_ep_req(usb->in_ep, usb->in_req);
		usb->in_req = NULL;
	}
	for (i = 0; i < ARRAY_SIZE(usb->out_req); i++) {
		if (usb->out_req[i]) {
			free_ep_req(usb->out_ep, usb->out_req[i]);
			usb->out_req[i] = NULL;
		}
	}

	mutex_lock(&abk_fido_dev.lock);
	abk_fido_dev.bound = false;
	abk_fido_dev.udc_name[0] = '\0';
	mutex_unlock(&abk_fido_dev.lock);
}

static int abk_fido_set_alt(struct usb_function *f, unsigned intf, unsigned alt)
{
	struct abk_fido_usb *usb = container_of(f, struct abk_fido_usb, func);
	struct usb_composite_dev *cdev = f->config->cdev;
	int i, ret;

	if (usb->in_req)
		abk_fido_disable(f);

	ret = config_ep_by_speed(cdev->gadget, f, usb->in_ep);
	if (ret)
		return ret;
	ret = usb_ep_enable(usb->in_ep);
	if (ret)
		return ret;
	usb->in_ep->driver_data = usb;

	ret = config_ep_by_speed(cdev->gadget, f, usb->out_ep);
	if (ret)
		goto err_in;
	ret = usb_ep_enable(usb->out_ep);
	if (ret)
		goto err_in;
	usb->out_ep->driver_data = usb;

	usb->in_req = alloc_ep_req(usb->in_ep, ABK_FIDO_REPORT_LEN);
	if (!usb->in_req) {
		ret = -ENOMEM;
		goto err_out;
	}
	usb->in_req->complete = abk_fido_tx_complete;
	usb->in_req->context = usb;

	for (i = 0; i < ARRAY_SIZE(usb->out_req); i++) {
		usb->out_req[i] = alloc_ep_req(usb->out_ep, ABK_FIDO_REPORT_LEN);
		if (!usb->out_req[i]) {
			ret = -ENOMEM;
			goto err_out;
		}
		usb->out_req[i]->complete = abk_fido_out_complete;
		usb->out_req[i]->context = usb;
		usb->out_req[i]->length = ABK_FIDO_REPORT_LEN;
		ret = usb_ep_queue(usb->out_ep, usb->out_req[i], GFP_KERNEL);
		if (ret)
			goto err_out;
	}

	usb->protocol = HID_REPORT_PROTOCOL;
	usb->idle = 0;
	usb->online = true;

	mutex_lock(&abk_fido_dev.lock);
	abk_fido_dev.bound = true;
	strscpy(abk_fido_dev.udc_name, cdev->gadget->name,
		sizeof(abk_fido_dev.udc_name));
	mutex_unlock(&abk_fido_dev.lock);

	abk_fido_tx_kick(usb);
	return 0;

err_out:
	abk_fido_disable(f);
	return ret;
err_in:
	usb_ep_disable(usb->in_ep);
	return ret;
}

static void abk_fido_free_func(struct usb_function *f)
{
	struct abk_fido_usb *usb = container_of(f, struct abk_fido_usb, func);

	cancel_work_sync(&usb->rx_work);
	if (usb->misc_registered) {
		misc_deregister(&usb->miscdev);
		usb->misc_registered = false;
	}
	kfree(usb);
}

static void abk_fido_unbind(struct usb_configuration *c, struct usb_function *f)
{
	struct abk_fido_usb *usb = container_of(f, struct abk_fido_usb, func);

	if (usb->misc_registered) {
		misc_deregister(&usb->miscdev);
		usb->misc_registered = false;
	}
	usb_free_all_descriptors(f);
	cancel_work_sync(&usb->rx_work);

	mutex_lock(&abk_fido_dev.lock);
	if (abk_fido_dev.usb == usb)
		abk_fido_dev.usb = NULL;
	abk_fido_dev.bound = false;
	abk_fido_dev.hid_name[0] = '\0';
	abk_fido_dev.udc_name[0] = '\0';
	mutex_unlock(&abk_fido_dev.lock);
}

static int abk_fido_bind(struct usb_configuration *c, struct usb_function *f)
{
	struct abk_fido_usb *usb = container_of(f, struct abk_fido_usb, func);
	int id, ret;

	id = usb_string_ids_tab(c->cdev, abk_fido_strings);
	if (id < 0)
		return id;

	abk_fido_intf_desc.iInterface = abk_fido_strings[ABK_FIDO_STRING_INTERFACE].id;
	id = usb_interface_id(c, f);
	if (id < 0)
		return id;
	abk_fido_intf_desc.bInterfaceNumber = id;

	usb->in_ep = usb_ep_autoconfig(c->cdev->gadget, &abk_fido_fs_in_desc);
	if (!usb->in_ep)
		return -ENODEV;
	usb->out_ep = usb_ep_autoconfig(c->cdev->gadget, &abk_fido_fs_out_desc);
	if (!usb->out_ep)
		return -ENODEV;

	abk_fido_hs_in_desc.bEndpointAddress = abk_fido_fs_in_desc.bEndpointAddress;
	abk_fido_hs_out_desc.bEndpointAddress = abk_fido_fs_out_desc.bEndpointAddress;
	abk_fido_ss_in_desc.bEndpointAddress = abk_fido_fs_in_desc.bEndpointAddress;
	abk_fido_ss_out_desc.bEndpointAddress = abk_fido_fs_out_desc.bEndpointAddress;
	abk_fido_hid_desc.desc[0].bDescriptorType = HID_DT_REPORT;
	abk_fido_hid_desc.desc[0].wDescriptorLength =
		cpu_to_le16(ABK_FIDO_REPORT_DESC_LEN);

	ret = usb_assign_descriptors(f, abk_fido_fs_descs, abk_fido_hs_descs,
				     abk_fido_ss_descs, abk_fido_ss_descs);
	if (ret)
		return ret;

	usb->miscdev.minor = MISC_DYNAMIC_MINOR;
	usb->miscdev.name = usb->misc_name;
	usb->miscdev.fops = &abk_fido_misc_fops;
	usb->miscdev.mode = 0600;
	ret = misc_register(&usb->miscdev);
	if (ret) {
		usb_free_all_descriptors(f);
		return ret;
	}
	usb->misc_registered = true;

	mutex_lock(&abk_fido_dev.lock);
	abk_fido_dev.usb = usb;
	strscpy(abk_fido_dev.hid_name, usb->misc_name, sizeof(abk_fido_dev.hid_name));
	mutex_unlock(&abk_fido_dev.lock);
	return 0;
}

static const struct config_item_type abk_fido_func_type = {
	.ct_owner = THIS_MODULE,
};

static void abk_fido_free_inst(struct usb_function_instance *fi)
{
	struct abk_fido_opts *opts = container_of(fi, struct abk_fido_opts, func_inst);

	mutex_lock(&abk_fido_ida_lock);
	ida_free(&abk_fido_ida, opts->minor);
	mutex_unlock(&abk_fido_ida_lock);
	kfree(opts);
}

static struct usb_function_instance *abk_fido_alloc_inst(void)
{
	struct abk_fido_opts *opts;
	int minor;

	opts = kzalloc(sizeof(*opts), GFP_KERNEL);
	if (!opts)
		return ERR_PTR(-ENOMEM);

	mutex_lock(&abk_fido_ida_lock);
	minor = ida_alloc_range(&abk_fido_ida, 0, 3, GFP_KERNEL);
	mutex_unlock(&abk_fido_ida_lock);
	if (minor < 0) {
		kfree(opts);
		return ERR_PTR(minor);
	}

	opts->minor = minor;
	opts->func_inst.free_func_inst = abk_fido_free_inst;
	config_group_init_type_name(&opts->func_inst.group, "", &abk_fido_func_type);
	return &opts->func_inst;
}

static struct usb_function *abk_fido_alloc(struct usb_function_instance *fi)
{
	struct abk_fido_opts *opts = container_of(fi, struct abk_fido_opts, func_inst);
	struct abk_fido_usb *usb;

	usb = kzalloc(sizeof(*usb), GFP_KERNEL);
	if (!usb)
		return ERR_PTR(-ENOMEM);

	spin_lock_init(&usb->tx_lock);
	INIT_WORK(&usb->rx_work, abk_fido_rx_worker);
	abk_fido_queue_init(&usb->rx_packets);
	abk_fido_queue_init(&usb->debug_rx);
	abk_fido_queue_init(&usb->tx_packets);
	usb->owner = &abk_fido_dev;
	snprintf(usb->misc_name, sizeof(usb->misc_name), "hidg%d", opts->minor);

	usb->func.name = "abk_fido";
	usb->func.strings = abk_fido_func_strings;
	usb->func.bind = abk_fido_bind;
	usb->func.unbind = abk_fido_unbind;
	usb->func.set_alt = abk_fido_set_alt;
	usb->func.disable = abk_fido_disable;
	usb->func.setup = abk_fido_setup;
	usb->func.free_func = abk_fido_free_func;
	return &usb->func;
}

DECLARE_USB_FUNCTION(abk_fido, abk_fido_alloc_inst, abk_fido_alloc);

static ssize_t enabled_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "1\n");
}

static ssize_t bound_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	bool bound;

	mutex_lock(&abk_fido_dev.lock);
	bound = abk_fido_dev.bound;
	mutex_unlock(&abk_fido_dev.lock);
	return sysfs_emit(buf, "%u\n", bound);
}

static ssize_t udc_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	ssize_t ret;

	mutex_lock(&abk_fido_dev.lock);
	ret = sysfs_emit(buf, "%s\n", abk_fido_dev.udc_name);
	mutex_unlock(&abk_fido_dev.lock);
	return ret;
}

static ssize_t hid_dev_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	ssize_t ret;

	mutex_lock(&abk_fido_dev.lock);
	ret = sysfs_emit(buf, "%s\n", abk_fido_dev.hid_name);
	mutex_unlock(&abk_fido_dev.lock);
	return ret;
}

static ssize_t ctap_dev_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "/dev/abk_fido_ctap\n");
}

static ssize_t credential_count_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	unsigned int count;

	mutex_lock(&abk_fido_dev.lock);
	count = abk_fido_count_credentials_locked();
	mutex_unlock(&abk_fido_dev.lock);
	return sysfs_emit(buf, "%u\n", count);
}

static ssize_t last_error_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	ssize_t ret;

	mutex_lock(&abk_fido_dev.lock);
	ret = sysfs_emit(buf, "%s\n", abk_fido_dev.last_error);
	mutex_unlock(&abk_fido_dev.lock);
	return ret;
}

static ssize_t last_trace_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	ssize_t ret;

	mutex_lock(&abk_fido_dev.lock);
	ret = sysfs_emit(buf, "%s\n", abk_fido_dev.last_trace);
	mutex_unlock(&abk_fido_dev.lock);
	return ret;
}

static ssize_t store_generation_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	ssize_t ret;

	mutex_lock(&abk_fido_dev.lock);
	ret = sysfs_emit(buf, "%u\n", abk_fido_dev.store_generation);
	mutex_unlock(&abk_fido_dev.lock);
	return ret;
}

static ssize_t reload_store_store(struct kobject *kobj, struct kobj_attribute *attr,
				  const char *buf, size_t count)
{
	(void)kobj;
	(void)attr;
	int ret;

	if (!(sysfs_streq(buf, "1") || sysfs_streq(buf, "reload") ||
	      sysfs_streq(buf, "restore")))
		return -EINVAL;

	mutex_lock(&abk_fido_dev.lock);
	ret = abk_fido_reload_store_locked();
	mutex_unlock(&abk_fido_dev.lock);
	return ret ? ret : count;
}

static ssize_t restore_metadata_store(struct kobject *kobj,
				      struct kobj_attribute *attr,
				      const char *buf, size_t count)
{
	(void)kobj;
	(void)attr;
	int ret;

	if (!(sysfs_streq(buf, "1") || sysfs_streq(buf, "restore") ||
	      sysfs_streq(buf, "reload")))
		return -EINVAL;

	mutex_lock(&abk_fido_dev.lock);
	ret = abk_fido_restore_persisted_store_locked("restore_metadata");
	mutex_unlock(&abk_fido_dev.lock);
	return ret ? ret : count;
}

static ssize_t auth_gate_enabled_show(struct kobject *kobj,
				      struct kobj_attribute *attr, char *buf)
{
	ssize_t ret;

	mutex_lock(&abk_fido_dev.lock);
	ret = sysfs_emit(buf, "%u\n", abk_fido_dev.auth_gate_enabled);
	mutex_unlock(&abk_fido_dev.lock);
	return ret;
}

static ssize_t auth_gate_enabled_store(struct kobject *kobj,
				       struct kobj_attribute *attr,
				       const char *buf, size_t count)
{
	bool enabled;

	if (sysfs_streq(buf, "1") || sysfs_streq(buf, "true") || sysfs_streq(buf, "on"))
		enabled = true;
	else if (sysfs_streq(buf, "0") || sysfs_streq(buf, "false") || sysfs_streq(buf, "off"))
		enabled = false;
	else
		return -EINVAL;

	mutex_lock(&abk_fido_dev.lock);
	abk_fido_dev.auth_gate_enabled = enabled;
	abk_fido_set_last_trace_locked("auth gate %s", enabled ? "enabled" : "disabled");
	mutex_unlock(&abk_fido_dev.lock);
	return count;
}

static ssize_t auth_pending_show(struct kobject *kobj,
				 struct kobj_attribute *attr, char *buf)
{
	ssize_t ret;

	mutex_lock(&abk_fido_dev.lock);
	ret = sysfs_emit(buf, "%u\n", abk_fido_dev.auth_pending);
	mutex_unlock(&abk_fido_dev.lock);
	return ret;
}

static ssize_t auth_request_id_show(struct kobject *kobj,
				    struct kobj_attribute *attr, char *buf)
{
	ssize_t ret;

	mutex_lock(&abk_fido_dev.lock);
	ret = sysfs_emit(buf, "%u\n", abk_fido_dev.auth_request_id);
	mutex_unlock(&abk_fido_dev.lock);
	return ret;
}

static ssize_t auth_context_show(struct kobject *kobj,
				 struct kobj_attribute *attr, char *buf)
{
	ssize_t ret;

	mutex_lock(&abk_fido_dev.lock);
	ret = sysfs_emit(buf,
			 "req=%u pending=%u cmd=%s rp=%s uv=%u rk=%u\n",
			 abk_fido_dev.auth_request_id,
			 abk_fido_dev.auth_pending,
			 abk_fido_ctap_name(abk_fido_dev.auth_pending_ctap_cmd),
			 abk_fido_dev.auth_pending_rp_id,
			 abk_fido_dev.auth_pending_uv,
			 abk_fido_dev.auth_pending_rk);
	mutex_unlock(&abk_fido_dev.lock);
	return ret;
}

static ssize_t auth_decision_store(struct kobject *kobj,
				   struct kobj_attribute *attr,
				   const char *buf, size_t count)
{
	bool allow;
	u32 request_id = 0;
	bool check_id = false;
	int ret;

	if (sysfs_streq(buf, "allow")) {
		allow = true;
	} else if (sysfs_streq(buf, "deny")) {
		allow = false;
	} else if (sscanf(buf, "allow %u", &request_id) == 1) {
		allow = true;
		check_id = true;
	} else if (sscanf(buf, "deny %u", &request_id) == 1) {
		allow = false;
		check_id = true;
	} else {
		return -EINVAL;
	}

	mutex_lock(&abk_fido_dev.lock);
	ret = abk_fido_auth_decide_locked(allow, request_id, check_id);
	if (!ret)
		abk_fido_set_last_trace_locked("auth %s req=%u",
			allow ? "allow" : "deny", abk_fido_dev.auth_request_id);
	mutex_unlock(&abk_fido_dev.lock);
	return ret ? ret : count;
}

static struct kobj_attribute enabled_attr = __ATTR_RO(enabled);
static struct kobj_attribute bound_attr = __ATTR_RO(bound);
static struct kobj_attribute udc_attr = __ATTR_RO(udc);
static struct kobj_attribute hid_dev_attr = __ATTR_RO(hid_dev);
static struct kobj_attribute ctap_dev_attr = __ATTR_RO(ctap_dev);
static struct kobj_attribute credential_count_attr = __ATTR_RO(credential_count);
static struct kobj_attribute last_error_attr = __ATTR_RO(last_error);
static struct kobj_attribute last_trace_attr = __ATTR_RO(last_trace);
static struct kobj_attribute store_generation_attr = __ATTR_RO(store_generation);
static struct kobj_attribute reload_store_attr = __ATTR_WO(reload_store);
static struct kobj_attribute restore_metadata_attr = __ATTR_WO(restore_metadata);
static struct kobj_attribute auth_gate_enabled_attr = __ATTR_RW(auth_gate_enabled);
static struct kobj_attribute auth_pending_attr = __ATTR_RO(auth_pending);
static struct kobj_attribute auth_request_id_attr = __ATTR_RO(auth_request_id);
static struct kobj_attribute auth_context_attr = __ATTR_RO(auth_context);
static struct kobj_attribute auth_decision_attr = __ATTR_WO(auth_decision);
static struct bin_attribute store_blob_attr = {
	.attr = {
		.name = "store_blob",
		.mode = 0600,
	},
	.size = sizeof(struct abk_fido_store_disk),
	.read = abk_fido_store_blob_read,
	.write = abk_fido_store_blob_write,
};

static struct attribute *abk_fido_attrs[] = {
	&enabled_attr.attr,
	&bound_attr.attr,
	&udc_attr.attr,
	&hid_dev_attr.attr,
	&ctap_dev_attr.attr,
	&credential_count_attr.attr,
	&last_error_attr.attr,
	&last_trace_attr.attr,
	&store_generation_attr.attr,
	&reload_store_attr.attr,
	&restore_metadata_attr.attr,
	&auth_gate_enabled_attr.attr,
	&auth_pending_attr.attr,
	&auth_request_id_attr.attr,
	&auth_context_attr.attr,
	&auth_decision_attr.attr,
	NULL,
};

static const struct attribute_group abk_fido_attr_group = {
	.attrs = abk_fido_attrs,
};

#if IS_ENABLED(CONFIG_ABK_CONTROL)
static bool abk_fido_control_is_enabled(void *data)
{
	(void)data;
	return true;
}

static int abk_fido_control_set_enabled(bool enabled, void *data)
{
	(void)data;
	return enabled ? 0 : -EOPNOTSUPP;
}

static int abk_fido_control_run_command(const char *command, void *data)
{
	(void)data;
	int ret = -EINVAL;

	mutex_lock(&abk_fido_dev.lock);
	if (!strcmp(command, "reload") || !strcmp(command, "reload_store")) {
		ret = abk_fido_reload_store_locked();
	} else if (!strcmp(command, "restore") ||
		   !strcmp(command, "restore_metadata")) {
		ret = abk_fido_restore_persisted_store_locked("abk_control");
	} else if (!strcmp(command, "persist") || !strcmp(command, "persist_now")) {
		ret = abk_fido_maybe_persist_locked();
		if (!ret)
			abk_fido_dev.last_error[0] = '\0';
	} else if (!strcmp(command, "auth_allow")) {
		ret = abk_fido_auth_decide_locked(true, 0, false);
	} else if (!strcmp(command, "auth_deny")) {
		ret = abk_fido_auth_decide_locked(false, 0, false);
	} else if (!strcmp(command, "auth_gate_on")) {
		abk_fido_dev.auth_gate_enabled = true;
		ret = 0;
	} else if (!strcmp(command, "auth_gate_off")) {
		abk_fido_dev.auth_gate_enabled = false;
		ret = 0;
	} else if (!strcmp(command, "pin_reset")) {
		memset(abk_fido_dev.store.pin_hash, 0, sizeof(abk_fido_dev.store.pin_hash));
		abk_fido_dev.store.pin_set = false;
		abk_fido_dev.store.pin_retries = ABK_FIDO_PIN_RETRIES_DEFAULT;
		abk_fido_dev.store_dirty = true;
		ret = abk_fido_maybe_persist_locked();
	}
	if (ret && !abk_fido_dev.last_error[0])
		snprintf(abk_fido_dev.last_error, sizeof(abk_fido_dev.last_error),
			 "control command failed: %d", ret);
	mutex_unlock(&abk_fido_dev.lock);
	return ret;
}

static const struct abk_control_ops abk_fido_control_ops = {
	.id = "abk_fido_key",
	.name = "ABK FIDO Key",
	.version = "0.2.0",
	.description = "Kernel-side FIDO2 security key with metadata-backed persistence.",
	.module_dir = "drivers/abk_fido_key",
	.web_root = "",
	.extension_id = "abk_fido_store",
	.companion_package = "com.abk.extension.fido",
	.companion_display_name = "ABK FIDO Companion",
	.companion_asset_name = "abk-fido-companion-release.apk",
	.companion_download_url =
		"https://github.com/xingguangcuican6666/ABK_FIDO_KEY_MODULE/releases/latest/download/abk-fido-companion-release.apk",
	.service_activity = ".FidoBootstrapActivity",
	.has_web_ui = false,
	.has_action_script = false,
	.action_supported = false,
	.requires_companion_app = true,
	.settings_supported = false,
	.per_app_supported = false,
	.oobe_priority = 90,
	.is_enabled = abk_fido_control_is_enabled,
	.set_enabled = abk_fido_control_set_enabled,
	.run_command = abk_fido_control_run_command,
};
#endif

int abk_fido_key_prepare_config(struct usb_composite_dev *cdev,
				struct usb_configuration *cfg,
				struct list_head *func_list)
{
	struct usb_function_instance *fi;
	struct usb_function *f;
	struct usb_function *iter;

	if (!IS_ENABLED(CONFIG_ABK_FIDO_KEY_GADGET_AUTO_ATTACH))
		return 0;

	list_for_each_entry(iter, func_list, list) {
		if (iter->name && !strcmp(iter->name, "abk_fido"))
			return 0;
	}

	fi = usb_get_function_instance("abk_fido");
	if (IS_ERR(fi))
		return PTR_ERR(fi);

	f = usb_get_function(fi);
	if (IS_ERR(f)) {
		usb_put_function_instance(fi);
		return PTR_ERR(f);
	}

	list_add_tail(&f->list, func_list);
	return 0;
}
EXPORT_SYMBOL_GPL(abk_fido_key_prepare_config);

void abk_fido_key_release_config(struct list_head *func_list)
{
	struct usb_function *f, *tmp;

	list_for_each_entry_safe(f, tmp, func_list, list) {
		struct usb_function_instance *fi;

		if (!f->name || strcmp(f->name, "abk_fido"))
			continue;

		fi = (struct usb_function_instance *)f->fi;
		list_del(&f->list);
		usb_put_function(f);
		usb_put_function_instance(fi);
	}
}
EXPORT_SYMBOL_GPL(abk_fido_key_release_config);

static int __init abk_fido_core_init(void)
{
	int ret;

	pr_info("abk_fido_key: build marker dummy-mc-v2\n");

	abk_fido_dev.kobj = kobject_create_and_add("abk_fido_key", kernel_kobj);
	if (!abk_fido_dev.kobj)
		return -ENOMEM;
	init_waitqueue_head(&abk_fido_dev.auth_wait);
	abk_fido_dev.auth_gate_enabled = true;

	ret = sysfs_create_group(abk_fido_dev.kobj, &abk_fido_attr_group);
	if (ret) {
		kobject_put(abk_fido_dev.kobj);
		abk_fido_dev.kobj = NULL;
		return ret;
	}

	ret = sysfs_create_bin_file(abk_fido_dev.kobj, &store_blob_attr);
	if (ret) {
		sysfs_remove_group(abk_fido_dev.kobj, &abk_fido_attr_group);
		kobject_put(abk_fido_dev.kobj);
		abk_fido_dev.kobj = NULL;
		return ret;
	}

	memset(&abk_fido_user_usb, 0, sizeof(abk_fido_user_usb));
	abk_fido_user_usb.owner = &abk_fido_dev;
	abk_fido_user_usb.userspace = true;
	abk_fido_user_usb.online = true;
	INIT_WORK(&abk_fido_user_usb.rx_work, abk_fido_rx_worker);
	abk_fido_queue_init(&abk_fido_user_usb.rx_packets);
	abk_fido_queue_init(&abk_fido_user_usb.tx_packets);
	strscpy(abk_fido_user_usb.misc_name, "abk_fido_ctap",
		sizeof(abk_fido_user_usb.misc_name));
	abk_fido_user_usb.miscdev.minor = MISC_DYNAMIC_MINOR;
	abk_fido_user_usb.miscdev.name = abk_fido_user_usb.misc_name;
	abk_fido_user_usb.miscdev.fops = &abk_fido_user_fops;
	abk_fido_user_usb.miscdev.mode = 0600;
	ret = misc_register(&abk_fido_user_usb.miscdev);
	if (ret) {
		sysfs_remove_bin_file(abk_fido_dev.kobj, &store_blob_attr);
		sysfs_remove_group(abk_fido_dev.kobj, &abk_fido_attr_group);
		kobject_put(abk_fido_dev.kobj);
		abk_fido_dev.kobj = NULL;
		return ret;
	}
	abk_fido_user_registered = true;

	ret = usb_function_register(&abk_fidousb_func);
	if (ret) {
		cancel_work_sync(&abk_fido_user_usb.rx_work);
		misc_deregister(&abk_fido_user_usb.miscdev);
		abk_fido_user_registered = false;
		sysfs_remove_bin_file(abk_fido_dev.kobj, &store_blob_attr);
		sysfs_remove_group(abk_fido_dev.kobj, &abk_fido_attr_group);
		kobject_put(abk_fido_dev.kobj);
		abk_fido_dev.kobj = NULL;
		return ret;
	}
	abk_fido_usb_registered = true;

	abk_fido_dev.store.pin_retries = ABK_FIDO_PIN_RETRIES_DEFAULT;
#if IS_ENABLED(CONFIG_ABK_CONTROL)
	ret = abk_control_register(&abk_fido_control_ops);
	if (ret)
		pr_warn("abk_fido_key: control registration failed: %d\n", ret);
#endif
	abk_fido_bootstrap_companion_service();
	return 0;
}

static void __exit abk_fido_core_exit(void)
{
#if IS_ENABLED(CONFIG_ABK_CONTROL)
	abk_control_unregister(&abk_fido_control_ops);
#endif
	if (abk_fido_usb_registered) {
		usb_function_unregister(&abk_fidousb_func);
		abk_fido_usb_registered = false;
	}
	if (abk_fido_user_registered) {
		cancel_work_sync(&abk_fido_user_usb.rx_work);
		misc_deregister(&abk_fido_user_usb.miscdev);
		abk_fido_user_registered = false;
	}
	kvfree(abk_fido_dev.store_blob_staging);
	abk_fido_dev.store_blob_staging = NULL;
	abk_fido_dev.store_blob_staging_len = 0;
	if (abk_fido_dev.kobj) {
		sysfs_remove_bin_file(abk_fido_dev.kobj, &store_blob_attr);
		sysfs_remove_group(abk_fido_dev.kobj, &abk_fido_attr_group);
		kobject_put(abk_fido_dev.kobj);
		abk_fido_dev.kobj = NULL;
	}
}

module_init(abk_fido_core_init);
module_exit(abk_fido_core_exit);

MODULE_DESCRIPTION("ABK kernel-integrated FIDO2 HID gadget with metadata-backed persistence");
MODULE_LICENSE("GPL");
