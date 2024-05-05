import middy from '@middy/core'
import cors from '@middy/http-cors'
import httpErrorHandler from '@middy/http-error-handler'
import {getByUserId} from '../../bussinessLogic/todos.mjs'
import {S3Client} from '@aws-sdk/client-s3'
import {getUserId} from '../utils.mjs'
import {createLogger} from '../../utils/logger.mjs'


const logger = createLogger('http')
const s3Client = new S3Client()

const bucketName = process.env.IMAGES_S3_BUCKET
const urlExpiration = parseInt(process.env.SIGNED_URL_EXPIRATION)


export const handler = middy()
  .use(httpErrorHandler())
  .use(cors({
    credentials: true
  }))
  .handler(async (event) => {
    logger.info(`Processing getTodos event ${JSON.stringify(event, null, 2)}`)

    const userId = getUserId(event)

    const items = (await getByUserId(userId))

    return {
      statusCode: 200, body: JSON.stringify({
        items
      })
    }
  })
