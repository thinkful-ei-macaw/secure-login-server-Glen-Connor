const bcrypt = require('bcryptjs')
const AuthService = require('../auth/auth');

function requireAuth(req, res, next) {
    // console.log('requireAuth')
    // console.log(req.get('Authorization'))
    const authToken = req.get('Authorization') || ''
    let basicToken;
    if (!authToken.toLowerCase().startsWith('basic')) {
        return res.status(401).json({ error: 'Missing basic token' })
    } else {
        basicToken = authToken.slice('basic '.length, authToken.length)
    }

    const [tokenUserName, tokenPassword] = AuthService.parseBasicToken(basicToken);


    if (!tokenUserName || !tokenPassword) {
        return res.status(401).json({ error: 'Unauthorized request' })
    }

    AuthService.getUserWithUserName(req.app.get('db'), tokenUserName)
        .then(
            (user) => {
                if (!user) {
                    return res.status(401).json({ error: 'Unathorized request' })
                }
                return bcrypt.compare(tokenPassword, user.password)
                    .then(passwordsMatch => {
                        if (!passwordsMatch) {
                            return res.status(401).json({ error: 'Unauthorized Request' })
                        }
                        req.user = user
                        next();
                    })
                    .catch(next)

            }
        )
}


module.exports = {
    requireAuth
}