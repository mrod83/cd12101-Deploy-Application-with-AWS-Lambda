import * as uuid from 'uuid'
import {TodosAccess} from "../dataLayer/todosAccess.mjs";
import {createLogger} from "../utils/logger.mjs";

const logger = createLogger('businessLogic')

const todosAccess = new TodosAccess();

export async function getByUserId(userId) {
  logger.info(`getByUserId ${userId}`)
  return todosAccess.getByUserId(userId);
}

export async function createTodo(createTodoRequest, userId) {
  const todoId = uuid.v4()
  logger.info(`createTodo ${userId} todoId ${todoId}`)

  return await todosAccess.create({
    todoId, userId, createdAt: new Date().toISOString(), done: false, ...createTodoRequest
  });
}

export async function updateTodo(userId, todoId, updateTodoRequest) {
  logger.info(`updateTodo ${userId} todoId ${todoId} request ${JSON.stringify(updateTodoRequest, null, 2)}`)
  return await todosAccess.update(userId, todoId, {...updateTodoRequest});
}

export async function setAttachmentUrl(userId, todoId, image, attachmentUrl) {
  logger.info(`setAttachmentUrl ${userId} todoId ${todoId} attachmentUrl ${attachmentUrl}`)
  return await todosAccess.setAttachmentUrl(userId, todoId, image, attachmentUrl);
}

export async function deleteTodo(userId, todoId) {
  logger.info(`createTodo ${userId} todoId ${todoId}`)
  return await todosAccess.delete(userId, todoId);
}
