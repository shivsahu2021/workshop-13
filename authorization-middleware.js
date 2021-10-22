const jwt = require("jsonwebtoken");
const config = require("./config");

module.exports = (credentials = []) => {
  return (req, res, next) => {
    console.log("Authorization middleware");
    
    if (typeof credentials === "string") {
      credentials = [credentials];
    }

    
    const token = req.headers["authorization"];
    if (!token) {
      return res.status(401).send("Sorry pal: access denied");
    } else {
      
  const tokenBody = token.slice(7);

      jwt.verify(tokenBody, config.JWT_SECRET, (err, decoded) => {
        if (err) {
          console.log(`JWT Error: ${err}`);
          return res.status(401).send("Error: Access Denied");
        }
        
        if (credentials.length > 0) {
          if (
            decoded.scopes &&
            decoded.scopes.length &&
            credentials.some(cred => decoded.scopes.indexOf(cred) >= 0)
          ) {
            next();
          } else {
            return res.status(401).send("Error: Access Denied");
          }
        } else {
          
          next();
        }
      });
    }
  };
};
