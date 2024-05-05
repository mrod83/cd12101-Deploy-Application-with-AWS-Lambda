import middy from '@middy/core'
import cors from '@middy/http-cors'
import httpErrorHandler from '@middy/http-error-handler'
import {createLogger} from '../../utils/logger.mjs'
import {setAttachmentUrl} from '../../bussinessLogic/todos.mjs'
import {getUserId} from "../utils.mjs";
import {getFormattedUrl, getUploadUrl} from "../../fileStoreage/attachmentUtils.mjs";

const logger = createLogger('http')


export const handler = middy()
  .use(httpErrorHandler())
  .use(cors({
    credentials: true
  }))
  .handler(async (event) => {
    const todoId = event.pathParameters.todoId;
    logger.info(`Uploading attachment for ${todoId}`)

    const image = JSON.parse(event.body)
    const userId = getUserId(event);

    const attachmentUrl = getFormattedUrl(todoId)
    const uploadUrl = await getUploadUrl(todoId)

    await setAttachmentUrl(userId, todoId, image, attachmentUrl)

    return {
      statusCode: 201, body: JSON.stringify({
        uploadUrl
      })
    }
  })
