/*!
 *
 * \addtogroup CoAP_Library
 * \defgroup  CoAP_Library CoAP
 * @{
 */

#include "coap.h"


/*!******************************************************************************
* \brief Ges the version of a CoAP message
*
* Description:
*   The coapGetVersion function parses an incoming buffer and retrieves the CoAP
*   version. Once parsed the coapGetVersion function validates if the version is
*   correct.
*
*   http://tools.ietf.org/html/rfc7252#section-3
*
*
* \param U8 *pBuffer [in] - This parameter is a pointer to the buffer containing
*                           CoAP message to be pasrsed.
*
*
* \param U16 bufferLength [in] - This parameter indicates the size of the incoming
*                           buffer.
*
* \return Returns CoAP version if successful or < 0 if unsuccesful.
*
********************************************************************************/
int8_t coapGetVersion(uint8_t *pBuffer, uint16_t bufferLength)
{
   uint8_t *pointer = pBuffer;  // Used to index through the buffer.
   uint8_t byte;                // Used to decode the version.

   int8_t version;             // Used to store the version

   // Check to make sure the buffer is at least 4 bytes
   if( bufferLength < COAP_HDR_BYTES )
   {
      return COAP_INVALID_PACKET;
   }

   // Assign the first byte of the of the buffer.
   byte = *pointer;

   // The first 2 bits of the byte contain the version.
   version = (int8_t)(byte >> 6);

   // Check if the verison is valid
   if( !coapVersionIsValid(version) )
   {
      return COAP_INVALID_VERSION;
   }

   // Return the version
   return version;
}

/*!*******************************************************************************
 * \brief Determines if a CoAP version is valid
 *
 * Description:
 *   The coapVersionIsValid fucntion determines if a version parsed out of an
 *   incoming buffer is valid as per RFC 7252.
 *
 *   http://tools.ietf.org/html/rfc7252#section-3
 *
 *
 * \param S8 *version [in] - Version parsed from an incoming/outgoing variable.
 *
 *
 * \return Return true if CoAP version is correct or false if invalid.
 *
 ********************************************************************************/
bool coapVersionIsValid(int8_t version)
{
   // Check if the version if valid
   if( version != COAP_VERSION )
   {
      return false;
   }
   return true;
}

/*!******************************************************************************
* \brief Gets the message typpe
*
* Description:
*   The coapGetType function parses an incoming/outgoing buffer for the CoAP
*   message type contained within the buffer.  Once parsed it then determines
*   if the type is valid.
*
*   Position of Type field within CoAP header:
*       http://tools.ietf.org/html/rfc7252#section-3
*
*   List of all valid types:
*       http://tools.ietf.org/html/rfc7252#section-4.3
*
*
* \param  U8 *pBuffer [in] - A pointer to incoming/outgoing buffer containing CoAP
*                            packet.
*
* \param  U16 bufferLength [in] - Stores the length of *pBuffer.
*
*
* \return  Returns CoAP type if valid or < 0 for error.
*
********************************************************************************/
int8_t coapGetType(uint8_t *pBuffer, uint16_t bufferLength)
{
   uint8_t *pointer = pBuffer;  // Used to index the incoming buffer.
   uint8_t byte;                // Used to parse out the tye from the packet.

   int8_t type;                // Used to store the type of the packet.

   // Check if the incoming packets is at least 4 bytes
   if( bufferLength < COAP_HDR_BYTES )
   {
      return COAP_INVALID_PACKET;
   }

   // The type value is contained within the first byte of the buffer
   byte = *pointer;

   // The 2nd and 3rd bits of the first byte specify the type
   type = (int8_t)((byte >> 4) & 0x03);

   // Check if the type is valid
   if( !coapTypeIsValid(type) )
   {
      return COAP_INVALID_TYPE;
   }

   return type;

}

/*!******************************************************************************
* \brief Determines if the message type is valid
*
* Description:
*   The coapTypeIsValid function validates that a parsed CoAP type is an acceptable
*  CoAP type.
*
*   List of all valid types:
*       http://tools.ietf.org/html/rfc7252#section-4.3
*
*
* \param S8 *pVersion [in] - Version parsed from an incoming/outgoing variable.
*
*
* \return Returns true if CoAP type is valid or false if invalid.
*
********************************************************************************/
bool coapTypeIsValid(int8_t type)
{
   // Check if the type is valid
   if( type > 3 || type < 0)
   {
      return false;
   }

   return true;
}


/*!******************************************************************************
* \brief Gets the token length
*
* Description:
*   The coapGetTOkenLength function parses an incoming/outgoing buffer for the
*   token length of a CoAP packet.
*
*   Link to position of token length within CoAP header:
*           http://tools.ietf.org/html/rfc7252#section-3
*
*
*
* \param  U8 *pBuffer [in] - Pointer to incoming/outgoing buffer containing CoAP
*                            packet.
*
* \param U16 bufferLength [in] - Variable containing the length of the buffer.
*
*
* \return  Returns token length if succesful or < 0 if unsuccessful
*
********************************************************************************/
int8_t coapGetTokenLength(uint8_t *pBuffer, uint16_t bufferLength)
{
   uint8_t *pointer = pBuffer;   // Used to index the buffer.
   uint8_t byte;                 // Used to parse token length out of packet.

   int8_t tokenLength;          // Used to store the token length value.

   // Check if there are at least 4 bytes.
   if( bufferLength < COAP_HDR_BYTES )
   {
      return COAP_INVALID_PACKET;
   }

   // The token length are stored as the last 4 bits of the first byte
   byte = *pointer;

   // Assign the token length
   tokenLength = (int8_t)byte & 0x0F;

   // Check if the token length is valid.
   if( !coapTokenLengthIsValid(tokenLength) )
   {
      return COAP_INVALID_TOKEN_LENGTH;
   }

   return tokenLength;

}

/*!*****************************************************************************
 * \brief Determines if token length is valid
 *
 * Description:
 *   The functioncoapTokenLengthIsValid determines if a token length is valid
 *  as per RFC 7252.
 *
 *   Link to valid token length criteria:
 *           http://tools.ietf.org/html/rfc7252#section-3
 *
 *
 *
 * \param  S8 tokenLength [in] - A variable containing a token length value.
 *
 * \return  Returns true if valid, otherwise false.
 *
 ********************************************************************************/
bool coapTokenLengthIsValid(int8_t tokenLength)
{
   // Check if the token length is in a valid range (0-8) bytes
   if( tokenLength >= 9 )
   {
      return false;
   }

   return true;
}

/*!*****************************************************************************
 * \brief Gets the code contained in a CoAP message
 *
 * Description:
 *   The function coapGetCode parses an incoming/outgoing buffer containing a
 *   CoAP packet and retrieves the code.
 *
 * Link to valid token length criteria:
 *           http://tools.ietf.org/html/rfc7252#section-12.1.2
 * Link to CoAP message format for Code Location in header:
 *           http://tools.ietf.org/html/rfc7252#section-3
 *
 *
 *
 * \param  U8 *pBuffer [in] - Buffer containing CoAP packet.
 *
 * \param  U16 bufferLength [in] - Variable containing buffer length.
 *
 *
 * \return Returns CoAP code if valid, otherwise returns < 0 for error.
 *
 ********************************************************************************/
int16_t coapGetCode(uint8_t *pBuffer, uint16_t bufferLength)
{
   uint8_t *pointer = pBuffer;   // Used to index the buffer.
   uint8_t byte;                 // Used to parse out code value

   int8_t code;                // Used to store the CoAP packet code.

   // Check that the buffer has at least 4 bytes.
   if( bufferLength < COAP_HDR_BYTES )
   {
      return COAP_INVALID_PACKET;
   }

   // Index the pointer.
   pointer++;

   // The code value is contained within the second byte of the CoAP packet
   byte = *pointer;

   // Parse out the code value
   code = (int16_t)byte;

   // Check if the code is valid.
   if( !coapCodeIsValid(code) )
   {
      return COAP_UNKNOWN_CODE;
   }

   return code;
}

/*!*****************************************************************************
 * \brief Deteremines if CoAP code is valid
 *
 * Description:
 *   The function coapCodeIsValid determines if a code parsed from a CoAP packet
 *   is valid.
 *
 *   Link to valid codes:
 *           http://tools.ietf.org/html/rfc7252#section-12.1.2
 *
 *
 *
 * \param  S16 code - A variable containing a parsed CoAP code.
 *
 *
 * \return Returns true if valid, otherwise false.
 *
 ********************************************************************************/
bool coapCodeIsValid(int16_t code)
{
   bool isValid = false;
   switch( code )
   {
   case COAP_EMPTY:

      isValid = true;
      break;

   case COAP_GET:

      isValid = true;
      break;

   case COAP_POST:

      isValid = true;
      break;

   case COAP_PUT:

      isValid = true;
      break;

   case COAP_DELETE:

      isValid = true;
      break;

   case COAP_CREATED:

      isValid = true;
      break;

   case COAP_DELETED:

      isValid = true;
      break;

   case COAP_VALID:

      isValid = true;
      break;

   case COAP_CHANGED:

      isValid = true;
      break;

   case COAP_CONTENT:

      isValid = true;
      break;

   case COAP_BAD_REQUEST:

      isValid = true;
      break;

   case COAP_UNAUTHORIZED:

      isValid = true;
      break;

   case COAP_BAD_OPTION:

      isValid = true;
      break;

   case COAP_FORBIDDEN:

      isValid = true;
      break;

   case COAP_NOT_FOUND:

      isValid = true;
      break;

   case COAP_METHOD_NOT_ALLOWED:

      isValid = true;
      break;

   case COAP_NOT_ACCEPTABLE:

      isValid = true;
      break;

   case COAP_PRECONDITION_FAILED:

      isValid = true;
      break;

   case COAP_REQUEST_ENTITY_TOO_LARGE:

      isValid = true;
      break;

   case COAP_UNSUPPORTED_CONTENT:

      isValid = true;
      break;

   case COAP_INTERNAL_SERVER_ERROR:

      isValid = true;
      break;

   case COAP_NOT_IMPLEMENTED:

      isValid = true;
      break;

   case COAP_BAD_GATEWAY:

      isValid = true;
      break;

   case COAP_SERVICE_UNAVAILABLE:

      isValid = true;
      break;

   case COAP_GATEWAY_TIMEOUT:

      isValid = true;
      break;

   case COAP_PROXYING_NOT_SUPPORTED:

      isValid = true;
      break;

   default:

      break;
   }

   return isValid;
}

/*!*****************************************************************************
 * \brief Gets the CoAP message id
 *
 * Description:
 *   The function coapGetMessageId parses the message id out of a buffer containing
 *   a CoAP packet.
 *
 *   Link to header format:
 *           https://tools.ietf.org/html/rfc7252#section-3
 *
 *
 *
 * \param  U8 *pBuffer [in] - Pointer to a buffer containing CoAP packet.
 *
 * \param  U16 bufferLength [in] - Variable containing the buffer length.
 *
 *
 * \return  Returns message id if valid or < 0 if unsuccessful.
 *
 ********************************************************************************/
int16_t coapGetMessageId(uint8_t *pBuffer, uint16_t bufferLength)
{
   uint8_t *pointer = pBuffer;   // Used to index the buffer.
   uint8_t firstHalf;            // Used to parse the first 8 bytes of the mid.
   uint8_t secondHalf;           // Used to parse the second 8 bytes of the mid

   int16_t messageId;           // Used to store the message id.

   // Check if the buffer is at least 4 bytes
   if( bufferLength < COAP_HDR_BYTES )
   {
      return COAP_INVALID_PACKET;
   }

   // Assign the first 8 bytes of the mid.
   firstHalf = *(pointer + 2);

   // Assign the second 8 bytes of the mid.
   secondHalf = *(pointer + 3);

   // Store the message id
   messageId = ( (int16_t)(firstHalf) << 8 | (int16_t)(secondHalf) );

   return messageId;

}

/*!*****************************************************************************
 * \brief Gets the token within a CoAP message
 *
 * Description:
 *   The function coapGetToken parses out the token length field and determines
 *   how many bytes the token is.  Once parsed the function stores the token bytes
 *   in the variable pointer *pToken.
 *
 *   Link to header format:
 *           https://tools.ietf.org/html/rfc7252#section-3
 *
 *
 * \param  U8 *pBuffer [in] - Pointer to a buffer containing CoAP packet.
 *
 * \param  U16 bufferLength [in] - Variable containing the buffer length.
 *
 * \param  U8 *pToken [in/out] - Variable where token bytes will be stored.
 *
 *
 * \return  Returns COAP_OK on sucesss or < 0 for error.
 *
 ********************************************************************************/
int8_t coapGetToken(uint8_t *pBuffer, uint16_t bufferLength, uint8_t *pToken)
{
   uint8_t *pointer = pBuffer;   // Used to index the buffer.
   int8_t tokenLength;          // Used to store the token length.

   // Check if the buffer contains at least 4 bytes
   if( bufferLength < COAP_HDR_BYTES )
   {
      return COAP_INVALID_PACKET;
   }
   else  //If valid then retrieve the token length
   {
      tokenLength = coapGetTokenLength(pBuffer, bufferLength);

      // Check if there was an error
      if( tokenLength < 0 )
      {
         // Return the error value in tokenLength
         return tokenLength;
      }
   }

   // Check that there is enough space in the buffer
   if( (COAP_HDR_BYTES + tokenLength) > bufferLength )
   {
      return COAP_INSUFFICIENT_BUFFER;
   }
   else  // Extract the token bytes
   {
      // Skip the header bytes.
      pointer += COAP_HDR_BYTES;

      if( tokenLength > 0 )
      {
         // Assign the token bytes.
         memcpy(pToken, pointer, tokenLength);
      }
   }

   return COAP_OK;
}

/*!*****************************************************************************
 * \brief Gets the option count contained within a CoAP message
 *
 * Description:
 *   The function coapGetOptionCount retrieves the number of options contained
 *   wihtin an incoming/outgoing buffer.
 *
 * Link to header format:
 *           https://tools.ietf.org/html/rfc7252#section-3
 *
 *
 * \param  U8 *pBuffer [in] - Pointer to a buffer containing CoAP packet.
 *
 * \param  U16 bufferLength [in] - Variable containing the buffer length.
 *
 * \return Returns option count on success otherwise < 0 for error.
 *
 ********************************************************************************/
int32_t coapGetOptionCount(uint8_t *pBuffer, uint16_t bufferLength)
{
   uint8_t *pointer = pBuffer;   // Used to index the buffer.
   uint8_t additionalByte;       // Used to construct option header.
   uint8_t byte;                 // Used to construct option header.
   uint8_t optionLength = 0;     // Used to store the length of data of a option instance.

   int8_t tokenLength;
   int32_t count = 0;            //used to store the option count

   uint16_t newLength = bufferLength;     //used to keep track of the difference in length

   // Check if there are at least 4 btyes
   if( bufferLength < COAP_HDR_BYTES )
   {
      return COAP_INVALID_PACKET;
   }
   else
   {
      // Extract the token length
      tokenLength = coapGetTokenLength(pBuffer, bufferLength);

      // Check for errors
      if( tokenLength < 0 )
      {
         // Return the error stored in tokenLength
         return tokenLength;
      }
   }

   // Determine if there are any options to count
   if( (COAP_HDR_BYTES + tokenLength) == bufferLength )
   {
      //no options to count return count = 0.
      return count;
   }
   else
   {
      //skip the header bytes and the token bytes
      pointer += COAP_HDR_BYTES + tokenLength;

      //update newLength
      newLength -= (COAP_HDR_BYTES + tokenLength);
   }

   //initially assign the byte value
   byte = *pointer;

   //loop through the remaining bytes of the buffer and determine the count
   while( byte != COAP_PAYLOAD_MARKER && newLength != 0 )
   {

      //determine the option length
      optionLength = ( (byte & 0x0F) );

      switch( optionLength )
      {
      case 0x0F:

         //invalid option formatting
         return COAP_INVALID_PACKET;

      case 0x0E:

         //increment the option count
         count++;

         //index the buffer to the next byte
         pointer++;

         //assign the additional byte
         additionalByte = *pointer;

         //add 269 to the option length becuase of CoAP option format
         optionLength = additionalByte + 269;

         //subtract the optionLength + the additional byte
         //to get the new length of the buffer
         newLength -= (optionLength + 2);

         //incremement the pointer to retrieve the next byte
         pointer += (optionLength + 1);

      case 0x0D:

         //incrememnt the count
         count++;

         //index the buffer to the next byte
         pointer++;

         //assign the additional byte
         additionalByte = *pointer;

         //add 13 to the optionLength because of CoAP option format
         optionLength = additionalByte + 13;

         //subtract the optionLength + the additional byte to get the
         //new length of the buffer
         newLength -= (optionLength + 2);

         //increment the pointer to retrieve the next byte
         pointer += (optionLength + 1);

         break;
      default:

         //increment the count
         count++;

         //subtract the option length to get the new length of the buffer
         newLength -= (optionLength + 1);

         //increment the pointer to retrieve the next byte
         pointer += (optionLength + 1);

         break;
      }

      // Assign the next byte within the array
      byte = *pointer;
   }
   return count;
}

/*!*****************************************************************************
 * \brief Gets an option within a CoAP message
 *
 * Description:
 *   The function coapGetOption retrieves an option at the user indicated index.
 *
 * Link to header format:
 *           https://tools.ietf.org/html/rfc7252#section-3
 *
 *
 * \param  U8 *pBuffer [in] - Pointer to a buffer containing CoAP packet.
 *
 * \param  U16 bufferLength [in] - Variable containing the buffer length.
 *
 * \param  U8 optionIndex [in] - Variable containing the option index to be parsed.
 *
 * \param  U8 *pOptionNumber [in/out] - Place holder for the option number of user
 *                                      specified option index.
 *
 * \param  U8 **pOptionData [in/out] - Place holder for option data contained within
 *                                     option at the user specified index.
 *
 * \param  U8 *pNewPointer [in/out] - Pointer to the next index within the buffer after
 *                                    option instance.
 *
 * \return  Returns COAP_OK on sucess or < 0 if unsuccessful.
 *
 ********************************************************************************/
int32_t coapGetOption(uint8_t *pBuffer, uint16_t bufferLength, uint8_t optionIndex, uint8_t *pOptionNumber, uint8_t **pOptionData, uint8_t *pNewPointer)
{
   uint8_t *pointer = pBuffer;   // Used to index through the buffer.
   uint8_t *newPointer;          // Used to help index through the option decoder.
   uint8_t *optionData;          // Used to store the option data
   uint8_t optionLength = 0;     // Used to store the option length.
   uint8_t optionNumber;         // Used to store the option number.
   uint8_t i;                    // Used as an iterator.
   uint16_t newLength;           // Used to keep track of the length left in buffer.
   int8_t tokenLength;          // Used to store the token length.

   // Check if the buffer has at least 4 bytes.
   if( bufferLength < COAP_HDR_BYTES )
   {
      return COAP_INVALID_PACKET;
   }
   else  // Extract the token length
   {
      tokenLength = coapGetTokenLength(pBuffer, bufferLength);

      // Check if coapGetTokenLength returned an error.
      if( tokenLength < 0)
      {
         // Return the error stored in tokenLength.
         return tokenLength;
      }
   }

   // Check if there is enough buffer left
   if( (bufferLength - (COAP_HDR_BYTES + tokenLength) == 0) )
   {
      return COAP_END_OF_PACKET;
   }

   // Skip the header and token bytes.
   pointer += (COAP_HDR_BYTES + tokenLength);

   // Keep track of new length
   newLength = bufferLength - (COAP_HDR_BYTES + tokenLength);

   // First option instance # is always 0
   optionNumber = 0;

   for( i=0; i < optionIndex; i++ )
   {
      // Check if the current position is not the payload byte
      if( *pointer == COAP_PAYLOAD_MARKER )
      {
         return COAP_FOUND_PAYLOAD_MARKER;
      }

      // Extract the option length
      optionLength = coapDecodeOption(pointer, newLength, &optionNumber, &optionData, &newPointer);

      // Check if there were errors from coapDecodeOption
      if( optionLength < 0 )
      {
         // Return the error stored in optionLength
         return optionLength;
      }

      // Position pointer at next option intsance.
      pointer = newPointer;
   }

   // Assign the option number
   if( optionNumber != 0 )
   {
      *pOptionNumber = optionNumber;
   }

   // Assign the option data
   if( optionData != 0 )
   {
      *pOptionData = optionData;
   }

   return optionLength;
}

/*!*****************************************************************************
 * \brief Decodes a CoAP option
 *
 * Description:
 *   The function coapDecodeOption takes an option instance and decodes the values
 *   contained within a buffer to determine what optin it is.
 *
 * Link to option format:
 *           https://tools.ietf.org/html/rfc7252#section-3.1
 *
 *
 * \param  U8 *pBuffer [in] - Pointer to a buffer containing CoAP packet.
 *
 * \param  U16 bufferLength [in] - Variable containing the buffer length.
 *
 * \param  U8 optionIndex [in] - Variable containing the option index to be parsed.
 *
 * \param  U8 *pOptionNumber [in/out] - Place holder for the option number of user
 *                                      specified option index.
 *
 * \param  U8 **pOptionData [in/out] - Place holder for option data contained within
 *                                     option at the user specified index.
 *
 * \param  U8 **pNewPointer [in/out] - Pointer to the next index within the buffer after
 *                                     option instance.
 *
 *
 *
 * \return  Returns optionLength on sucess, otherwise < 0 for error.
 *
 ********************************************************************************/
int32_t coapDecodeOption(uint8_t *pPointer, uint16_t bufferLength, uint8_t *pOptionNumber, uint8_t **pOptionData, uint8_t **pNewPointer)
{

   uint8_t optionDelta;                // Used to keep track of delta for TLV format.

   uint16_t optionLength;              // Used to keep track of the length of the option

   // Check for end of packet
   if( bufferLength == 0 )
   {
      return COAP_END_OF_PACKET;
   }

   // Check for payload marker
   if( *pPointer == COAP_PAYLOAD_MARKER )
   {
      return COAP_FOUND_PAYLOAD_MARKER;
   }

   // The option delta is stored as the first bits
   optionDelta = *pPointer >> 4;

   // The option length is stored as the last four bits
   optionLength = *pPointer & 0x0F;

   // Increment the pointer.
   pPointer++;

   // Check for formatting errors and extended delta
   if( optionDelta == 0x0F )
   {
      // Return a formatting error.
      return COAP_INVALID_PACKET;
   }
   else if( optionDelta == 0x0E )
   {
      // As per RFC 7572 add 269 to the delta value
      optionDelta = (*pPointer << 8) + *(pPointer + 1) + 269;

      // Increment the pointer
      pPointer += 2;
   }
   else if( optionDelta == 0x0D )
   {
      // As per RFC 7572 add 13 to the delta value
      optionDelta = *pPointer + 13;

      // Increment the pointer.
      pPointer += 1;
   }
   else if( optionDelta < 0x0D )
   {
      optionDelta = optionDelta;
   }
   else
   {
      return COAP_INVALID_PACKET;
   }

   // Check for formatting errors and extended length.
   if( optionLength == 0x0F )
   {
      // Return a formatiing error.
      return COAP_INVALID_PACKET;
   }
   else if( optionLength == 0x0E )
   {
      // As per RFC 7572 add 269 to the delta value
      optionLength = (*pPointer << 8) + *(pPointer + 1) + 269;

      // Increment the pointer
      pPointer += 2;
   }
   else if( optionLength == 0x0D )
   {
      // As per RFC 7572 add 13 to the delta value
      optionLength = *pPointer + 13;

      // Increment the pointer.
      pPointer += 1;
   }
   else if( optionLength < 0x0D )
   {
      optionLength = optionLength;
   }
   else
   {
      return COAP_INVALID_PACKET;
   }

   // Assign the option number
   if( pOptionNumber != NULL )
   {
      *pOptionNumber += optionDelta;
   }

   // Assign the option data
   if( pOptionData != NULL )
   {
      *pOptionData = pPointer;
   }

   // Position the pointer at the next option instance.
   pPointer += optionLength;

   // Position at the next potential index.
   *pNewPointer = pPointer;

   return optionLength;

}

/*!*****************************************************************************
 * \brief Gets a CoAP payload
 *
 * Description:
 *   The function coapDecodeOption takes an option instance and decodes the values
 *   contained within a buffer to determine what optin it is.
 *
 * Link to header format:
 *           https://tools.ietf.org/html/rfc7252#section-3.1
 *
 *
 * \param  U8 *pBuffer [in] - Pointer to a buffer containing CoAP packet.
 *
 * \param  U16 bufferLength [in] - Variable containing the buffer length.
 *
 * \param  U8 optionIndex [in] - Variable containing the option index to be parsed.
 *
 * \param  **pPayloadData [in/out] - Variable to point to the payload data contained
 *                                   within a buffer.
 *
 *
 * \return  Returns payload length on sucess and < 0 for error.
 *
 ********************************************************************************/
int16_t coapGetPayload(uint8_t *pBuffer, uint16_t bufferLength, uint8_t **pPayloadData)
{
   uint8_t *pointer = pBuffer;   // Used to index the buffer.
   uint8_t byte;                 // Used to decode bytes in the buffer.
   uint8_t additionalByte;       // Used to decode the additional TLV byte.

   int16_t newLength;           // Used to keep track of the length.

   int8_t tokenLength;          // Used to store the token length.

   int32_t optionLength = 0;    // Used to store the option length.
   int32_t optionCount;         // Used to store the option count.
   int32_t payloadSize = 0;     // Used to store the payload size.

   // Check if packet is at least 4 bytes
   if( bufferLength < COAP_HDR_BYTES )
   {
      return COAP_INVALID_PACKET;
   }
   else
   {
      // Store the length.
      newLength = bufferLength;

      // Get the option count.
      optionCount = coapGetOptionCount(pBuffer, bufferLength);

      // Get the token length.
      tokenLength = coapGetTokenLength(pBuffer, bufferLength);

      // Check for errors.
      if(  optionCount < 0 )
      {
         // Return the error stored in optionCount
         return optionCount;
      }
      else if( tokenLength < 0 )
      {
         // Return the error stored in tokenLength
         return tokenLength;
      }
      else
      {
         // Check that there is enough buffer.
         if( (COAP_HDR_BYTES + tokenLength) > bufferLength )
         {
            return COAP_INSUFFICIENT_BUFFER;
         }
         else if( (COAP_HDR_BYTES + tokenLength) == bufferLength )
         {
            // No buffer left for paylaod.
            return payloadSize;
         }

         // No errors.  Add index the pointer pass the header and token bytes.
         pointer += COAP_HDR_BYTES + tokenLength;

         // Subtract the header and token length.
         newLength -= (int16_t)COAP_HDR_BYTES + tokenLength;
      }
   }

   // Assign the byte the pointer is pointing to.
   byte = *pointer;

   if( optionCount == 0 && byte == COAP_PAYLOAD_MARKER )
   {
      // Copy the payload data skipping the payload marker.
      pointer++;
      newLength -= 1;
      *pPayloadData = pointer;
      //memcpy( pPayloadData, pointer, newLength );

      // Return the size of the paylaod.
      return (int16_t)newLength;
   }
   else if( optionCount > 0 && byte == COAP_PAYLOAD_MARKER )
   {
      // Return a formatting error.
      return COAP_INVALID_PACKET;
   }
   else  // Option Count is > 0
   {
      //loop through the remaining bytes of the buffer and determine the count
      while( byte != COAP_PAYLOAD_MARKER || newLength == 0)
      {

         // Determine the option length.
         optionLength = ( (byte & 0x0F) );

         switch( optionLength )
         {
         case 0x0F:

            // Invalid option formatting.
            return COAP_INVALID_PACKET;

         case 0x0E:

            // Index the buffer to the next byte.
            pointer++;

            // Assign the additional byte
            additionalByte = *pointer;

            // Add 269 to the option length becuase of CoAP option format.
            optionLength = additionalByte + 269;

            // Subtract the optionLength + the additional byte
            // to get the new length of the buffer.
            newLength -= (optionLength + 2);

            // Incremement the pointer to retrieve the next byte.
            pointer += (optionLength + 1);

         case 0x0D:

            // Index the buffer to the next byte.
            pointer++;

            // Assign the additional byte.
            additionalByte = *pointer;

            // Add 13 to the optionLength because of CoAP option format.
            optionLength = additionalByte + 13;

            // Subtract the optionLength + the additional byte to get the
            // new length of the buffer.
            newLength -= (optionLength + 2);

            // Increment the pointer to retrieve the next byte.
            pointer += (optionLength + 1);

            break;
         default:

            // Subtract the option length to get the new length of the buffer.
            newLength -= (optionLength + 1);

            // Increment the pointer to retrieve the next byte.
            pointer += (optionLength + 1);

            break;
         }

         // Assign the next byte within the array
         byte = *pointer;

         // Decrement the optionCount variable.
         optionCount--;
      }

      // Check the case that broke the loop
      if( byte == COAP_PAYLOAD_MARKER && newLength != 0 )
      {
         // Assign the payload data skipping the payload marker.
         pointer++;
         newLength -= 1;

         *pPayloadData = pointer;

      }
      else
      {
         // Return a formatting error
         return COAP_INVALID_PACKET;
      }
   }
   return newLength;
}


/*!*****************************************************************************
 * \brief Gets the size of a CoAP message
 *
 * Description:
 *   This function determines the length of a CoAP message by using a pointer
 *   to the buffer where the message is stored.
 *
 * Link to header format:
 *           https://tools.ietf.org/html/rfc7252#section-3.1
 *
 *
 * \param  U8 *pBuffer [in] - Pointer to a buffer containing CoAP packet.
 *
 * \return  Returns the message size of the CoAP message.
 *
 ********************************************************************************/
int16_t coapGetSize(uint8_t *pBuffer)
{
   uint8_t *pointer = pBuffer;
   int16_t count = 0;


   while( *pointer != 0 )
   {
      // Increment the count.
      count++;

      // Incrment the pointer.
      pointer++;

   }

   return count;
}

/*!*****************************************************************************
 * \brief Sets the Version of a CoAP message
 *
 * Description:
 *   The function coapSetVersion encodes a specified version into a buffer.  This
 *   function also determines if the version number is valid.
 *
 * Link to header format:
 *           https://tools.ietf.org/html/rfc7252#section-3.1
 *
 *
 * \param  U8 *pBuffer [in\out] - pBuffer will update with encoded version.
 *
 * \param  U16 pBufferLength [in\out] - Variable that updates buffer length with encoded
 *                                version.
 *
 * \param  U8 version [in] - Variable containing the version to be encoded.
 *
 *
 * \return  Returns COAP_OK on success, otherwise < 0 for error.
 *
 ********************************************************************************/
int8_t coapSetVersion(uint8_t *pBuffer, uint16_t *pBufferLength, uint8_t version)
{

   // Check that the version is valid.
   if( !coapVersionIsValid(version) )
   {
      return COAP_INVALID_VERSION;
   }

   // As per RFC 7252, version is included as the first 2 bits of the first btye.
   pBuffer[0] = (version << 6) | (pBuffer[0] & 0x3F);

   // Set the length.
   *pBufferLength = 1;

   return COAP_OK;
}

/*!*****************************************************************************
 * \brief Sets the type of a CoAP message
 *
 * Description:
 *   The function coapSetType encodes a specified type into a buffer.  This func-
 *   tion also determines if the CoAP type passed in is valid.
 *
 * Header format:
 *          https://tools.ietf.org/html/rfc7252#section-3
 *
 *
 * \param  U8 *pBuffer [in\out] - pBuffer will update with encoded type.
 *
 * \param  U16 *pBufferLength [in\out] - Variable that updates buffer length.
 *
 * \param U8 type [in] - Variable containing the type to be encoded.
 *
 *
 * \return  Returns payload length on sucess and < 0 for error.
 *
 ********************************************************************************/
int8_t coapSetType(uint8_t *pBuffer, uint16_t *pBufferLength, uint8_t type)
{
   // Check that the type is valid.
   if( !coapTypeIsValid(type) )
   {
      return COAP_INVALID_TYPE;
   }

   // As per RFC 7252, type is included in the first byte.
   pBuffer[0] = (type << 4) | (pBuffer[0] & 0xCF);

   // Set the buffer length
   *pBufferLength = 1;

   return COAP_OK;

}

/*!*****************************************************************************
 * \brief Sets the token length
 *
 * Description:
 *   The function coapSetToken length will take the input parameter and ecnode
 *   the token length into the CoAP header.
 *
 * Header format:
 *          https://tools.ietf.org/html/rfc7252#section-3
 *
 *
 * \param  U8 *pBuffer [in\out] - pBuffer will update.
 *
 * \param  U16 *pBufferLength [in\out] - Variable that updates buffer length.
 *
 * \param  U8 tokenLength [in] - Variable containing the token length to be encoded
 *
 *
 * \return Returns COAP_OK on success and < 0 for error.
 *
 ********************************************************************************/
int8_t coapSetTokenLength(uint8_t *pBuffer, uint16_t *pBufferLength, uint8_t tokenLength)
{
   // Check if the token length is valid
   if( !coapTokenLengthIsValid(tokenLength) )
   {
      return COAP_INVALID_TOKEN_LENGTH;
   }

   // As per RFC 7252, token length is included in the first byte of the header.
   pBuffer[0] = (tokenLength & 0x0F) | pBuffer[0];

   // Set the buffer length.
   *pBufferLength = 1;

   return COAP_OK;
}

/*!*****************************************************************************
 * \brief Sets the code of a CoAP message
 *
 * Description:
 *   The function coapSetCode takes an a code value as an input parameter and
 *   encodes this value into the header of a CoAP packet.
 *
 * Header format:
 *          https://tools.ietf.org/html/rfc7252#section-3
 *
 *
 * \param  U8 *pBuffer [in\out] - pBuffer will update.
 *
 * \param  U16 *pBufferLength [in\out] - Variable that updates buffer length.
 *
 * \param  CoapCode code [in] - Variable containing the CoAP code to be encoded.
 *
 *
 * \return Returns COAP_OK on success and < 0 for error.
 *
 ********************************************************************************/
int8_t coapSetCode(uint8_t *pBuffer, uint16_t *pBufferLength, CoapCode code)
{
   // Check if the code is valid
   if( !coapCodeIsValid(code) )
   {
      return COAP_UNKNOWN_CODE;
   }

   // As per RFC 7252, code is included as the second byte of the message header.
   pBuffer[1] = code;

   // Set the buffer length.
   *pBufferLength = 2;

   return COAP_OK;

}

/*!*****************************************************************************
 * \brief Sets the message id
 *
 * Description:
 *   The function coapSetMessageId takes a message id input and encodes this value
 *   into the header of a CoAP packet.
 *
 *  Header format:
 *          https://tools.ietf.org/html/rfc7252#section-3
 *
 *
 * \param U8 *pBuffer [in\out] - pBuffer will update.
 *
 * \param U16 bufferLength [in\out] - Variable that updates buffer length.
 *
 * \param  U16 messageId [in] - Variable containing the message id to be encoded into
 *                              the buffer.
 *
 * \return  Returns COAP_OK on success or < 0 for error.
 *
 ********************************************************************************/
int8_t coapSetMessageId(uint8_t *pBuffer, uint16_t *pBufferLength, uint16_t messageId)
{
   // As per RFC 7572, message id is included as the 3rd and 4th bytes of the
   // message header.
   pBuffer[2] = messageId >> 8;
   pBuffer[3] = messageId & 0xFF;

   // Set the new buffer length.
   *pBufferLength = COAP_HDR_BYTES;

   return COAP_OK;
}

/*!*****************************************************************************
 * \brief Sets the token
 *
 * Description:
 *   The function coapSetToken takes the pointer *pToken and ecnodes the bytes
 *   contained wihtin this pointer.
 *
 * Header format:
 *          https://tools.ietf.org/html/rfc7252#section-3
 *
 *
 * \param  U8 *pBuffer [in\out] - pBuffer will update.
 *
 * \param  U16 *bufferLength [in\out] - Variable that updates buffer length.
 *
 * \param  U8 *pToken - Pointer to token bytes to be encoded.
 *
 * \param  U8 pTokenLength - Variable containing the length of the token bytes to be
 *                           enocoded.
 *
 *
 * \return  Returns COAP_OK on success and < 0 for error.
 *
 ********************************************************************************/
int8_t coapSetToken(uint8_t *pBuffer, uint16_t *pBufferLength, uint8_t *pToken, uint8_t tokenLength)
{

   // Check that the token length is valid.
   if( !coapTokenLengthIsValid(tokenLength) )
   {
      return COAP_INVALID_TOKEN_LENGTH;
   }

   // Skip the header bytes.
   pBuffer += COAP_HDR_BYTES;

   // Copy the token bytes to the buffer.
   memcpy(pBuffer, pToken, tokenLength);

   // Set the new length.
   *pBufferLength = COAP_HDR_BYTES + tokenLength;

   return COAP_OK;
}

/*!*****************************************************************************
 * \brief Adds an option to a CoAP message
 *
 * Description:
 *   The function coapAddOption encodes a new option instance into a buffer.
 *
 * Option format:
 *          https://tools.ietf.org/html/rfc7252#section-3.1
 *
 *
 * \param  U8 *pBuffer [in\out] - pBuffer will update.
 *
 * \param  U16 pBufferLength [in\out] - Variable that updates buffer length.
 *
 * \param  U8 option [in] - Option number to be encoded
 *
 * \param  U8 *pOptionData [in] - Pointer to option data to be encoded.
 *
 * \param  U8 **pNewPointer [in\out] - Variable that will contain the next writeable
 *                                     index within the buffer.
 *
 *
 * \return Returns COAP_OK on success or < 0 if unsuccesful.
 *
 ********************************************************************************/
int8_t coapAddOption(uint8_t *pBuffer, uint16_t *pBufferLength, uint8_t option, uint8_t optionLength, uint8_t *pOptionData, uint8_t **pNewPointer)
{

   uint8_t *pointer = pBuffer;  // Used to index the pBuffer.
   uint8_t tokenLength;         // Used to store the token length.
   uint8_t *previousOptionData;  // Used to store the previous optionData;
   uint8_t *newPointer = *pNewPointer;
   int8_t optionHeaderLength;  // Used to store the option header.
   int8_t optionCount;         // Used to store the option count;
   int8_t previousOption;      // Used to store the previous option number.

   // Check that the header is at least 4 bytes before adding options.
   if( *pBufferLength < COAP_HDR_BYTES )
   {
      return COAP_INVALID_PACKET;
   }
   else
   {
      // Extract the token length.
      tokenLength = coapGetTokenLength(pBuffer, *pBufferLength);

      // Extract the option count.
      optionCount = coapGetOptionCount(pBuffer, *pBufferLength);

      // Check for errors
      if( tokenLength < 0 )
      {
         // Return the error stored in tokenLength.
         return tokenLength;
      }
      else if( optionCount < 0 )
      {
         // Return the error stored in optionCount.
         return optionCount;
      }
   }

   // Check that the option passed in is valid
   if( !coapOptionIsValid(option) )
   {
      return COAP_INVALID_OPTION;
   }
   else
   {
      // Check if there are other options.
      if( optionCount > 0 )
      {
         // Get the last option number.  Subtract one from optionCount because
         // of zero based indexing.
         coapGetOption(pBuffer, *pBufferLength, optionCount, &previousOption, &previousOptionData, newPointer);
      }
      else
      {
         // Already checked for errors so this must be the first option instance.
         previousOption = 0;

         // If there are no option instances place insertion point past header
         // and token bytes.
         newPointer += COAP_HDR_BYTES + tokenLength;
      }
   }

   // Compute the option header length.
   optionHeaderLength = coapBuildOptionHeaderLength(option, optionLength, previousOption);

   // Check for errors within optionHeaderLength.
   if( optionHeaderLength < 0 )
   {
      // Return the error stored in optionHeaderLength.
      return optionHeaderLength;
   }

   // Check that the buffer will not overflow.
   if( (COAP_HDR_BYTES + tokenLength + optionLength + optionHeaderLength) > MAX_BUFFER_SIZE )
   {
      return COAP_INSUFFICIENT_BUFFER;
   }

   // Check that the option isn't being placed in the middle of the buffer.
   if( (newPointer - pBuffer) != *pBufferLength && *pNewPointer != 0 )
   {
      return COAP_INVALID_PACKET;
   }
   else
   {
      // Insert the option header.
      *pBufferLength = coapBuildOptionHeader(pBuffer, pBufferLength, option, previousOption, optionLength, optionHeaderLength, &newPointer);
   }

   // Check for an error.
   if( *pBufferLength < 0 )
   {
      // Return the error stored in pBufferLength.
      return *pBufferLength;
   }

   // Attach the option data.
   memcpy(newPointer, pOptionData, optionLength);

   // Calculate the new size.
   *pBufferLength += optionLength;

   // Update the pointer position.
   newPointer += optionLength;

   *pNewPointer = newPointer;

   return COAP_OK;

}

/*!*****************************************************************************
 * \brief Builds an option header
 *
 * Description:
 *   The function coapBuildOptionHeader builds the Type-Length-Value bytes for an
 *   option instance.
 *
 * Option format:
 *          https://tools.ietf.org/html/rfc7252#section-3.1
 *
 *
 * \param  U8 *pBuffer [in\out] - pBuffer will update.
 *
 * \param  U16 *pBufferLength [in\out] - Variable that updates buffer length.
 *
 * \param  U8 option [in] - Option number to be encoded
 *
 * \param  U8 *pOptionData [in] - Pointer to option data to be encoded.
 *
 * \param  U8 previousOption [in] - Variable storing the previous option number.
 *                                  Defaults to 0 if there wasn't a previous option.
 *
 * \param  U8 optionLength [in] - Contains the length of the option to be encoded.
 *
 * \param  U8 optionHeaderLength [in] - Variable containing the length of the option
 *                                      header.
 *
 * \param  U8 **pNewPointer [in\out] - Variable that will contain the next writeable
 *                                     index within the buffer.
 *
 *
 * \return  Returns the new buffer length on success or < 0 for error.
 *
 ********************************************************************************/
int8_t coapBuildOptionHeader(uint8_t *pBuffer, uint16_t *pBufferLength, uint8_t option, uint8_t previousOption, uint8_t optionLength, uint8_t optionHeaderLength, uint8_t **pNewPointer)
{
   uint8_t *pointer = *pNewPointer;  // Used to index the buffer.
   uint8_t *newPointer = *pNewPointer;
   uint8_t delta;                   // Used to store the delta value to encode.
   uint8_t length = optionLength;  // Used to store the length of the option.
   int8_t tokenLength;             // Used to store the token length.

   // Check that therere is at least 4 bytes
   if( *pBufferLength < COAP_HDR_BYTES )
   {
      return COAP_INVALID_PACKET;
   }

   // Check the the option passed in is valid.
   if( !coapOptionIsValid(option) || !coapOptionIsValid(previousOption) )
   {
      return COAP_INVALID_OPTION;
   }

   // Extract the token length.
   tokenLength = coapGetTokenLength(pBuffer, *pBufferLength);

   // check for errors within the tokenLength.
   if( tokenLength < 0 )
   {
      // Return the error stored in the token length.
      return tokenLength;
   }

   // Check there is enough space to add the the option.
   if( (COAP_HDR_BYTES + tokenLength + optionLength + optionHeaderLength) > MAX_BUFFER_SIZE )
   {
      return COAP_INSUFFICIENT_BUFFER;
   }

   // Calculate the difference.
   delta = option - previousOption;

   // Check that the option is not out of order.
   if( delta < 0 )
   {
      return COAP_OPTIONS_OUT_OF_ORDER;
   }

   // Determine the type of encoding needed for delta
   if( delta < 13 )
   {
      // Increment pNewPointer.
      newPointer++;
   }
   if( delta >= 13 && delta < 269 )
   {
      // As per RFC 7252 option formating.
      delta = 0x0D;

      // As per RFC 7252 option formatting.
      newPointer++;
      *newPointer = option - 13;
   }
   else if( delta >= 269 )
   {
      // As per RFC 7252 option formatting.
      delta = 0x0E;

      // Asign the additional byte.
      newPointer++;
      *newPointer = (delta - 269) >> 8;
      newPointer++;
      *newPointer = (delta - 269) & 0xFF;
   }



   if( optionLength >= 13 && optionLength < 269 )
   {
      // As per RFC 7252 option formatting.
      length = 0x0D;

      // Assign then increment.
      *newPointer = optionLength - 13;
      newPointer++;
   }
   else if( optionLength >= 269 )
   {
      // As per RFC 7252 option formatting.
      length = 0x0E;

      // Assign then increment.
      *newPointer = (optionLength - 269) >> 8;
      newPointer++;
      *newPointer = (optionLength - 269) & 0xFF;
      newPointer++;
   }

   // Assign the option header byte.
   *pointer = (delta & 0x0F) << 4 | length;

   // Store the new address.
   *pNewPointer = newPointer;

   return  (newPointer - pBuffer);
}

/*!*****************************************************************************
 * \brief Calculates the option header length
 *
 * Description:
 *   The function coapBuildOptionHeaderLength will calculate the length of the
 *   option header for an option instance.
 *
 * Option format:
 *          https://tools.ietf.org/html/rfc7252#section-3.1
 *
 *
 * \param  U8 option - Stores the current option number.
 *
 * \param  U8 optionLength - Stores the option length.
 *
 * \param  U8 previousOption - Stores the previous option value.  Defaults to 0 if there
 *                              wasn't a previous option value.
 *
 *
 * \return Returns option header length on success, or < 0 upon error.
 *
 ********************************************************************************/
int8_t coapBuildOptionHeaderLength(uint8_t option, uint8_t optionLength, uint8_t pPreviousOption)
{
   int8_t length = 1;   // Used to create the option header.
   int8_t delta;        // Used for delta encoding.
   int8_t difference;   // Used to calculate delta.

   // Check that the option is valid.
   if( !coapOptionIsValid(option) )
   {
      return COAP_INVALID_OPTION;
   }

   // Calcualate the difference.
   difference = option - pPreviousOption;

   // Check that the options are not out of order.
   if( difference < 0 )
   {
      return COAP_OPTIONS_OUT_OF_ORDER;
   }
   else
   {
      // Assign delta.
      delta = difference;
   }

   // Check the delta.
   if( delta < 13 )
   {
      // Do nothing.
   }
   else if( delta >= 13 && delta < 269 )
   {
      // Add one additional byte as per RFC 7252.
      length += 1;
   }
   else if( delta >= 269 )
   {
      // Add two additional byte as per RFC 7252.
      length += 2;
   }

   // Check the length.
   if( optionLength < 13 )
   {
      // Do nothing.
   }
   else if( optionLength >= 13 && optionLength < 269)
   {
      // Add one additional byte as per RFC 7252.
      length += 1;
   }
   else if( optionLength >= 269 )
   {
      // Add two additional bytes as per RFC 7252.
      length += 2;
   }

   return length;
}

/*!*****************************************************************************
 * \brief Determines if option is valid
 *
 * Description:
 *   This function determines if an option value is valid
 *
 * Option format:
 *          https://tools.ietf.org/html/rfc7252#section-3.1
 *
 * \param U8 *pBuffer [in\out] - pBuffer will update with encoded CoAP code.
 *
 * \param U16 *pBufferLength [in\out] - Variable that updates buffer length with encoded
 *                                      version.
 *
 * \param U8 option [in] - Option number to be encoded
 *
 * \param  U8 *pOptionData [in] - Pointer to option data to be encoded.
 *
 * \param U8 **pNewPointer [in\out] - Variable that will contain the next writeable
 *                               index within the buffer.
 *
 *
 * \return Returns COAP_OK on success or < 0 for error.
 *
 ********************************************************************************/
bool coapOptionIsValid(uint8_t option)
{
   //Check if the option ID passed in is a valid option
   if( option == 2 || option == 9 || option == 10 )
   {
      return false;
   }

   //check if a reserved option ID was passed into the parameter
   if( option == 128 || option == 132 || option == 136 || option == 140)
   {
      return false;
   }

   return true;
}

/*!*****************************************************************************
 * \brief Sets the payload
 *
 * Description:
 *  The function coapSetPayload will encode payload data to a buffer containing a
 *  CoAP packet.
 *
 * Packet format:
 *          https://tools.ietf.org/html/rfc7252#section-3.0
 *
 *
 * \param U8 *pBuffer [in\out] - Updates with the payload.
 *
 * \param U8 *pOptionLength [in\out] - Updates buffer length with payload attached.
 *
 * \param  U8 payloadLength [in] - Variable that stores the payload length.
 *
 * \param  U8 *pPayloadData [in] - Pointer to the payload data to be attached.
 *
 * \param  U8 *pPointer [in] - Pointer to assist indexing *pBuffer.
 *
 * \param  U8 **pNewPointer [in\out] - Updates to the end of the buffer.
 *
 *
 * \return Returns option header length on success, or < 0 upon error.
 *
 ********************************************************************************/
int32_t coapSetPayload(uint8_t *pBuffer, uint16_t *pBufferLength, uint16_t payloadLength, uint8_t *pPayloadData, uint8_t *pPointer, uint8_t **pNewPointer)
{

   uint8_t tokenLength;
   int i;

   // Check that the buffer has at least 4 bytes.
   if( *pBufferLength < COAP_HDR_BYTES )
   {
      return COAP_INVALID_PACKET;
   }
   else
   {
      tokenLength = coapGetTokenLength(pBuffer, *pBufferLength);

      if( tokenLength < 0 )
      {
         // return the error stored in tokenLength
         return tokenLength;
      }
   }

   // Check that the payload length is valid
   if( payloadLength <= 0 )
   {
      return COAP_INVALID_PAYLOAD;
   }
   else if( payloadLength >= MAX_BUFFER_SIZE || (COAP_HDR_BYTES + tokenLength + payloadLength) > MAX_BUFFER_SIZE )
   {
      return COAP_INSUFFICIENT_BUFFER;
   }

   if( *pPayloadData != 0 )
   {
      *pPointer++ = COAP_PAYLOAD_MARKER;

      // Convert payload data to base16 string type.
//        for( i=0; i<payloadLength; i++ )
//        {
//            U8 *temp = pPayloadData;
//
//            itoa( temp, pPayloadData[i], 16 );
//
//            *pPointer++ = *temp;
//        }
      memcpy(pPointer, pPayloadData, payloadLength);


      *pNewPointer = (pPointer + payloadLength);

      // Update the buffer length.  Add one more for the payload marker.
      *pBufferLength += (payloadLength + 1);
   }

   return COAP_OK;
}


/*!*****************************************************************************
 * \brief Sets a CoAP header
 *
 * Description:
 *  The function coapSetPayload will encode payload data to a buffer containing a
 *  CoAP packet.
 *
 * Packet format:
 *          https://tools.ietf.org/html/rfc7252#section-3.0
 *
 *
 * \param U8 *pBuffer [in\out] - Updates the buffer with all of the input parameters.
 *
 * \param U16 *pBufferLength [in\out] - Updates buffer length.
 *
 * \param U8 pVersion [in] - User specified version.
 *
 * \param U8 type [in] - User specified type.
 *
 * \param U8 tokenLength [in] - User specified token length.
 *
 * \param  CoapCode code [in] - User specified code.
 *
 * \param  U16 messageId [in] - Randomly generated message id.  (Can be user specified).
 *
 * \param  U8 *pToken [in] - Pointer to token bytes if any.
 *
 *
 * \return Returns option header length on success, or < 0 if error.
 *
 ********************************************************************************/
int8_t coapSetPacketHeader(uint8_t *pBuffer, uint16_t *pBufferLength, uint8_t version, uint8_t type, uint8_t tokenLength, CoapCode code, uint16_t messageId)
{
   uint8_t results;

   // Set the version.
   results = coapSetVersion(pBuffer, pBufferLength, version);

   // Check for errors.
   if( results < 0 )
   {
      return results;
   }

   // Set the type
   results = coapSetType(pBuffer, pBufferLength, type);

   // Check for errors.
   if( results < 0 )
   {
      return results;
   }

   // Set the token length
   results = coapSetTokenLength(pBuffer, pBufferLength, tokenLength);

   // Check for errors.
   if( results < 0 )
   {
      return results;
   }

   results = coapSetCode(pBuffer, pBufferLength, code);

   // Check for errors.
   if( results < 0 )
   {
      return results;
   }

   // Set the message id
   coapSetMessageId(pBuffer, pBufferLength, messageId);

   return COAP_OK;
}

/*!*****************************************************************************
 * \brief Gets a random number
 *
 * Description:
 *  This function is used to get a random message id for a CoAP message.
 *
 * Packet format:
 *          https://tools.ietf.org/html/rfc7252#section-3.0
 *
 *
 * \return Returns a random U16
 *
 ********************************************************************************/
uint16_t coapGetRandom()
{
   return rand();
}

/*!*****************************************************************************
 * \brief Validates a CoAP message
 *
 * Description:
 *  Determines if a CoAP message is valid.
 *
 * Packet format:
 *          https://tools.ietf.org/html/rfc7252#section-3.0
 *
 * \param U8 *pBuffer [in] - Pointer to CoAP message
 *
 * \param U16 pBufferLength [in] - Variable that contains the length of the CoAP message
 *
 * \return Returns COAP_OK if valid or <0 if invalid.
 *
 ********************************************************************************/
int8_t coapValidatePacket(uint8_t *pBuffer, uint16_t bufferLength)
{

   int32_t optionCount;
   uint8_t tOptionNumber;
   uint8_t *tOptionData = NULL;
   uint8_t *pointer = pBuffer;
   uint8_t *newPointer = pointer;

   int i;

   // Check if only 4 bytes were sent.
   if( bufferLength == COAP_HDR_BYTES )
   {

      // Check if the version is valid.
      if( !coapVersionIsValid(coapGetVersion(pBuffer, bufferLength) ) )
      {
         return coapGetVersion(pBuffer, bufferLength);
      }

      // Check if the type is valid.
      if( !coapTypeIsValid(coapGetType(pBuffer, bufferLength) ) )
      {
         return coapGetType(pBuffer, bufferLength);
      }

      // Check if the token length is valid
      if( !coapTokenLengthIsValid(coapGetTokenLength(pBuffer, bufferLength) ) )
      {
         return coapGetTokenLength(pBuffer, bufferLength);
      }

      // Check if the code is valid.
      if( !coapCodeIsValid(coapGetType(pBuffer, bufferLength) ) )
      {
         return coapGetType(pBuffer, bufferLength);
      }
   }
   else
   {
      // Check if the version is valid.
      if( !coapVersionIsValid(coapGetVersion(pBuffer, bufferLength) ) )
      {
         return coapGetVersion(pBuffer, bufferLength);
      }

      // Check if the type is valid.
      if( !coapTypeIsValid(coapGetType(pBuffer, bufferLength) ) )
      {
         return coapGetType(pBuffer, bufferLength);
      }

      // Check if the token length is valid
      if( !coapTokenLengthIsValid(coapGetTokenLength(pBuffer, bufferLength) ) )
      {
         return coapGetTokenLength(pBuffer, bufferLength);
      }

      // Check if the code is valid.
      if( !coapCodeIsValid(coapGetType(pBuffer, bufferLength) ) )
      {
         return coapGetType(pBuffer, bufferLength);
      }

      // Retrieve option count.
      optionCount = coapGetOptionCount(pBuffer, bufferLength);

      // Check if there was an error.
      if( optionCount < 0 )
      {
         return false;
      }
      else
      {
         // Loop through and validate each option
         for( i=0; i<optionCount; i++ )
         {
            if( coapGetOption(pBuffer, bufferLength, i, &tOptionNumber, &tOptionData, newPointer) < 0 )
            {
               return coapGetOption(pBuffer, bufferLength, i, &tOptionNumber, &tOptionData, newPointer);
            }
         }
      }
   }
   return COAP_OK;
}

//! @}