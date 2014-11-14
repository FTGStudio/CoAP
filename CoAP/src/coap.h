/*!
 *
 * \addtogroup CoAP_Library
 * \defgroup  CoAP_Library CoAP
 * @{
 */
#ifndef COAP_H
#define COAP_H

#include "FreeRTOS.h"       // RTOS Kernel
#include "task.h"           // RTOS Kernel
#include "queue.h"          // RTOS Kernel
#include "types.h"          // typdefs
#include "diagprint.h"      // diagnosting printing
#include <time.h>           // needed for timestamp
#include <sys/time.h>       // needed for timestamp
#include "string.h"
#include "stdlib.h"

/*Server and URI Related*/
#define LED_ALIAS                   "led" //LEDs
#define CONFIG_ALIAS                "config2"
#define PACKET_ALIAS                "dataPacket"
#define URI_PREFIX                  "1a" //a part of the exosite URI "coap.exosite.com/1a/ALIAS/CIK"
#define SERVER_NAME                 "coap.exosite.com" //exosite server
#define COAP_PORT                   5683
#define MAX_BUFFER_SIZE             1460 //Max length for UDP packet

//CIK
//#define CIK                         "cf3f6fbf9496634fde805a7acb6ef81f65c583e3" //Test Module
#define CIK                           "6922d4889ffbaa190a35389fa26c355fc2710d8a" // example1
#define CIK_LENGTH                    40

/*CoAP Protocol Related*/
#define COAP_VERSION                (1)
#define COAP_DEFAULT_PORT           (5683)
#define COAP_MAX_RETRANS_COUNT      3
#define COAP_MAX_WAIT_COUNT         30 //seconds
#define COAP_CLEANUP_TIME_INTERVAL  60 //seconds
#define MAX_OPTION_COUNT            20
#define MAX_OPTION_LIST_SIZE        8
#define MAX_TOKEN_LENGTH            8
#define COAP_MIN_MESSAGE_SIZE       4

//COAP Header
#define COAP_HDR_BYTES              4
#define COAP_HDR_VER_MASK           0xC0
#define COAP_HDR_TYPE_MASK          0x30
#define COAP_HDR_TKL_MASK           0x0F
#define COAP_HDR_CODE_MASK          0xFF
#define COAP_HDR_MSG_ID_MASK_HIGH   0xFF00
#define COAP_HDR_MSG_ID_MASK_LOW    0x00FF
#define COAP_HDR_RST_MASK           0x00000000

//Payload Marker
#define COAP_PAYLOAD_MARKER         0xFF
#define COAP_OPTION_END             0xF0

// Message Buffer Variables
#define MAX_MESSAGE_QUEUE           100
#define MAX_RETRY                   3

#define TIME_STAMP_SIZE             4
#define PAYLOAD_HDR_SIZE            7

#define ACCEL_SIZE                  202
#define TEMP_SIZE                   4
#define GPS_SIZE                    31
#define LIGHT_SIZE                  2

#define NUM_INPUTS                  7

typedef enum
{
   COAP_OPTION_IF_MATCH = 1,
   COAP_OPTION_URI_HOST = 3,
   COAP_OPTION_ETAG = 4,
   COAP_OPTION_IF_NONE_MATCH = 5,
   COAP_OPTION_URI_PORT = 7,
   COAP_OPTION_LOCATION_PATH = 8,
   COAP_OPTION_URI_PATH = 11,
   COAP_OPTION_CONTENT_FORMAT = 12,
   COAP_OPTION_MAXAGE = 14,
   COAP_OPTION_URI_QUERY = 15,
   COAP_OPTION_ACCEPT = 17,
   COAP_OPTION_LOCATION_QUERY = 20,
   COAP_OPTION_PROXY_URI = 35,
   COAP_OPTION_PROXY_SCHEME = 39,
   COAP_OPTION_SIZE1 = 60

} CoapOptionType;

typedef enum
{
   COAP_TYPE_CON = 0,       ///< Confirmable message (requires ACK/RST)
   COAP_TYPE_NON = 1,       ///< Non-confirmable message (one-shot message)
   COAP_TYPE_ACK = 2,       ///< Acknowledge
   COAP_TYPE_RST = 3,        ///< Reset
}CoapMessageType;

/// CoapErrorCode enum
typedef enum
{
   COAP_OK = 0,                         ///< No error occured
   COAP_INVALID_PACKET = -1,            ///< Invalid Packet
   COAP_INVALID_VERSION = -2,           ///< Packet version is invalid
   COAP_INVALID_TOKEN_LENGTH = -3,      ///< Packet token length is invalid
   COAP_UNKNOWN_CODE = -4,              ///< Unknown code contained in message
   COAP_TOO_MANY_OPTIONS = -5,          ///< Too many options
   COAP_OPTIONS_OUT_OF_ORDER = -6,      ///< CoAP options out of order
   COAP_INSUFFICIENT_BUFFER = -7,       ///< CoAP message is too big
   COAP_FOUND_PAYLOAD_MARKER = -8,      ///< Payload marker at invalid index
   COAP_END_OF_PACKET = -9,             ///< End of packet
   COAP_INVALID_PAYLOAD = -10,          ///< Invalid Payload
   COAP_INVALID_OPTION = -11,           ///< Invalid option
   COAP_INVALID_OPTION_LIST = -12,      ///< Invalid option list
   COAP_MEMALLOCATE_FAILED = -13,       ///< Memory allocation failed
   COAP_INVALID_OPTION_DATA = -14,      ///< Invalid option data
   COAP_INVALID_BUFFER_LENGTH = -15,    ///< Invalid buffer length
   COAP_INVALID_TYPE = -16,             ///< Invalid CoAP type
   COAP_DID_NOT_FIND_CODE = -17         ///< CoAP did not find code
}CoapErrorCode;


/// CoapCode enum
typedef enum
{
   COAP_EMPTY = 0x00,                      ///< REST Command EMPTY
   COAP_GET = 0x01,                        ///< REST Command GET
   COAP_POST = 0x02,                       ///< REST Command POST
   COAP_PUT = 0x03,                        ///< REST Command PUT
   COAP_DELETE = 0x04,                     ///< REST Command DELETE
   COAP_CREATED = 0x41,                    ///< SUCCESS 2.01 Created
   COAP_DELETED = 0x42,                    ///< SUCCESS 2.02 Deleted
   COAP_VALID = 0x43,                      ///< SUCCESS 2.03 Valid
   COAP_CHANGED = 0x44,                    ///< SUCCESS 2.04 Changes
   COAP_CONTENT = 0x45,                    ///< SUCCESS 2.05 Content
   COAP_BAD_REQUEST = 0x80,                ///< CLIENT ERROR 4.00 Bad Request
   COAP_UNAUTHORIZED = 0x81,               ///< CLIENT_ERROR 4.01 Unauthorized
   COAP_BAD_OPTION = 0x82,                 ///< CLIENT_ERROR 4.02 Bad Option
   COAP_FORBIDDEN = 0x83,                  ///< CLIENT_ERROR 4.03 Forbidden
   COAP_NOT_FOUND = 0x84,                  ///< CLIENT_ERROR 4.04 Not Found
   COAP_METHOD_NOT_ALLOWED = 0x85,         ///< CLIENT_ERROR 4.05 Not Allowed
   COAP_NOT_ACCEPTABLE = 0x86,             ///< CLIENT_ERROR 4.06 Not Acceptable
   COAP_PRECONDITION_FAILED = 0x8C,        ///< CLIENT_ERROR 4.12 Precondition Failed
   COAP_REQUEST_ENTITY_TOO_LARGE = 0x8D,   ///< CLIENT_ERROR 4.13 Request Entity Too Large
   COAP_UNSUPPORTED_CONTENT = 0x8F,        ///< CLIENT_ERROR 4.15 Unsupported Content-Format
   COAP_INTERNAL_SERVER_ERROR = 0xA0,      ///< SERVER ERROR 5.00 Internal Server Error
   COAP_NOT_IMPLEMENTED = 0xA1,            ///< SERVER ERROR 5.01 Not Implemented
   COAP_BAD_GATEWAY = 0xA2,                ///< SERVER ERROR 5.02 Bad Gateway
   COAP_SERVICE_UNAVAILABLE = 0xA3,        ///< SERVER ERROR 5.03 Service Unavailable
   COAP_GATEWAY_TIMEOUT = 0xA4,            ///< SERVER ERROR 5.04 Gateway Timeout
   COAP_PROXYING_NOT_SUPPORTED = 0xA5      ///< SERVER ERROR 5.05 Proxying Not Supported

}CoapCode;


/// CoapAlias enum
typedef enum
{
   COAP_ALIAS_LIGHT_SENSOR = 0,         ///< Light Sensor
   COAP_ALIAS_TEMPERATURE = 1,          ///< Temperature Sensor
   COAP_ALIAS_ACCEL = 2,                ///< Accelerometer
   COAP_ALIAS_GPS = 3,                  ///< GPS
   COAP_ALIAS_LED = 4,                  ///< LED
   COAP_TEXT = 5                        ///< Text for the console
} CoapAlias;

extern xQueueHandle coapMsgQ;

void coapTask(void);

bool coapOptionIsValid(uint8_t option);
bool coapVersionIsValid(int8_t version);
bool coapTypeIsValid(int8_t type);
bool coapCodeIsValid(int16_t code);
bool coapTokenLengthIsValid(int8_t tokenLength);
int8_t coapGetVersion(uint8_t *pBuffer, uint16_t bufferLength);
int8_t coapGetType(uint8_t *pBuffer, uint16_t bufferLength);
int8_t coapGetTokenLength(uint8_t *pBuffer, uint16_t bufferLength);
int8_t coapGetToken(uint8_t *pBuffer, uint16_t bufferLength, uint8_t *pToken);
int16_t coapGetCode(uint8_t *pBuffer, uint16_t bufferLength);
int16_t coapGetMessageId(uint8_t *pBuffer, uint16_t bufferLength);
int16_t coapGetPayload(uint8_t *pBuffer, uint16_t bufferLength, uint8_t **pPayloadData);
int16_t coapGetSize(uint8_t *pBuffer);
int32_t coapGetOptionCount(uint8_t *pBuffer, uint16_t bufferLength);
int32_t coapGetOption(uint8_t *pBuffer, uint16_t bufferLength, uint8_t optionIndex, uint8_t *pOptionNumber, uint8_t **pOptionData, uint8_t *pNewPointer);

int8_t coapSetVersion(uint8_t *pBuffer, uint16_t *pBufferLength, uint8_t version);
int8_t coapSetType(uint8_t *pBuffer, uint16_t *pBufferLength, uint8_t type);
int8_t coapSetTokenLength(uint8_t *pBuffer, uint16_t *pBufferLength, uint8_t tokenLength);
int8_t coapSetCode(uint8_t *pBuffer, uint16_t *pBufferLength, CoapCode code);
int8_t coapSetToken(uint8_t *pBuffer, uint16_t *pBufferLength, uint8_t *pToken, uint8_t tokenLength);
int8_t coapSetPacketHeader(uint8_t *pBuffer, uint16_t *pBufferLength, uint8_t version, uint8_t type, uint8_t tokenLength, CoapCode code, uint16_t messageId);
int32_t coapSetPayload(uint8_t *pBuffer, uint16_t *pBufferLength, uint16_t payloadLength, uint8_t *pPayloadData, uint8_t *pPointer, uint8_t **pNewPointer);

// Adjusters/Decoders
int8_t coapAddOption(uint8_t *pBuffer, uint16_t *pBufferLength, uint8_t option, uint8_t optionLength, uint8_t *pOptionData, uint8_t **pNewPointer);
int8_t coapBuildOptionHeader(uint8_t *pBuffer, uint16_t *pBufferLength, uint8_t option, uint8_t previousOption, uint8_t optionLength, uint8_t optionHeaderLength, uint8_t **pNewPointer);
int8_t coapBuildOptionHeaderLength(uint8_t option, uint8_t optionLength, uint8_t pPreviousOption);
int8_t coapValidatePacket(uint8_t *pBuffer, uint16_t bufferLength);
int32_t coapDecodeOption(uint8_t *pBuffer, uint16_t bufferLength, uint8_t *pOptionNumber, uint8_t **optionData, uint8_t **pNewPointer);

//! @}
#endif  /* COAP_H */

