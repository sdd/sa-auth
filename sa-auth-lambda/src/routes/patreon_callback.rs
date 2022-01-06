use lambda_http::http::StatusCode;
use lambda_http::lambda_runtime::Error;
use lambda_http::{Context, Request, RequestExt, Response};

use crate::callback::{create_cookie_response, create_jwt};
use log::debug;
use papo_provider_core::OAuthProvider;
use papo_provider_patreon::{PatreonIdentityResponse, PatreonToken, PatronStatus};
use sa_auth_model::{PatreonTokenRepository, UserRepository};

use crate::context::AppContext;
use crate::me::get_claims_from_request;

pub async fn patreon_callback_handler(
    req: Request,
    _: Context,
    app_ctx: &AppContext,
) -> Result<Response<String>, Error> {
    // parse JWT from request cookie to get JWT claims
    if let Some(claims) = get_claims_from_request(&req, app_ctx) {
        if let Some(code) = req.query_string_parameters().get("code") {
            let code = code.to_string();
            let provider = &app_ctx.patreon_oauth_provider();

            // get access and refresh tokens from Patreon OAuth
            let token_response = provider.get_token(&code).await?;
            debug!(
                "Good Token Response from Patreon (scope {:?})",
                &token_response.scope
            );

            // use the tokens to query the patreon API to get the user's identity and membership status
            let identity: PatreonIdentityResponse =
                provider.get_identity(&token_response.access_token).await?;
            debug!(
                "Good Identity Response from Patreon (id {:?})",
                identity.data.id
            );

            // create a new identity table entry to store the access and refresh tokens
            let patreon_token =
                PatreonToken::from_token_response(token_response, &identity.data.id, &claims.sub);

            app_ctx
                .patreon_token_repository()
                .insert(&patreon_token)
                .await?;
            debug!("Patreon token successfully persisted");

            let campaign_patron_status = identity.best_patron_status();
            debug!("Patronage status:{:?}", &campaign_patron_status);

            // update the user to reflect their Supporter status and persist it.
            if let Some(mut user) = app_ctx.user_repository().get_by_id(&claims.sub).await? {
                debug!("User retrieved from db: id {:?}", &user.id);

                user.patreon_status = campaign_patron_status;
                user.patreon_connected = true;

                app_ctx.user_repository().insert(&user).await?;
                debug!("Promoted user successfully persisted to db");

                // re-issue their cookie with a fresh JWT containing their membership status. Redirect back to the app.
                let jwt = create_jwt(
                    &user.id,
                    &user.role,
                    app_ctx.cfg.jwt_secret.as_bytes(),
                    true,
                    user.patreon_status == PatronStatus::Active,
                )?;

                Ok(create_cookie_response(
                    jwt,
                    &app_ctx.cfg.auth_cookie_domain,
                    &app_ctx.cfg.auth_cookie_name,
                    &app_ctx.cfg.auth_cookie_path,
                    &app_ctx.cfg.success_redirect_url,
                ))
            } else {
                // user not found! Oh dear, should not happen
                debug!("User not found when linking Patreon! returning 500");
                Ok(Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body("User not found".to_string())
                    .unwrap())
            }
        } else {
            Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body("Missing code parameter".to_string())
                .unwrap())
        }
    } else {
        Ok(Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .body("401 Not Authorized".to_string())
            .unwrap())
    }
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;

    use super::*;
}
