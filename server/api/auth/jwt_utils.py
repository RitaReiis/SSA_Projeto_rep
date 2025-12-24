from flask import current_app
import jwt
import traceback

def issue_token(user_id: int, comp_id: int, is_admin: bool, is_agent: bool) -> str:
    """ Create a new token with user information """
    payload = {
        'user_id': user_id,
        'comp_id': comp_id,
        'is_admin': is_admin,
        'is_agent': is_agent,
    }
    private_key = current_app.config.get('JWT_PRIVATE_PEM')
    if private_key:
        try:
            token = jwt.encode(payload, key=private_key, algorithm='RS256')
            str_token = token.decode('utf-8') if isinstance(token, (bytes, bytearray)) else token
            return str_token
        except Exception as e:
            raise Exception('Issue RS256 token failed', e) from e

def validate_token(token: str):
    """ Validate JWT token """
    print("token", token)
    if not token:
        return False, None
    try:
        jwt.get_unverified_header(token)
    except Exception as e:
        print("Error decoding header", e, traceback.format_exc())
        return False, None

    try:
        public_key_pem = current_app.config.get('JWT_PUBLIC_PEM', '')
        if public_key_pem:
            # Use PEM string directly - PyJWT 1.5.0 should handle this
            payload = jwt.decode(
                token,
                key=public_key_pem,
            )
            return True, payload
    except Exception as e:
        print("Error decoding RS256 with public key", e)
        pass
    return False, None
