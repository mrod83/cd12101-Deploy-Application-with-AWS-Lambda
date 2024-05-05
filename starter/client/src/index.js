import { Auth0Provider } from '@auth0/auth0-react'
import React from 'react'
import ReactDOM from 'react-dom'
import 'semantic-ui-css/semantic.min.css'
import App from './App'
import './index.css'
import {AUTH0_CLIENT_ID, AUTH0_DOMAIN} from "./config";

const domain = AUTH0_DOMAIN
const clientId = AUTH0_CLIENT_ID
ReactDOM.render(
  <Auth0Provider
    domain={domain}
    clientId={clientId}
    redirectUri={window.location.origin}
    audience={`https://${domain}/api/v2/`}
    scope="read:todo write:todo delete:todo"
  >
    <App />
  </Auth0Provider>,
  document.getElementById('root')
)
