classDiagram
    class users {
        +id SERIAL
        username VARCHAR(255)
    }
    
    class invite_tokens {
        +token_id SERIAL
        user_id INTEGER
        token VARCHAR(255)
        created_at TIMESTAMP WITH TIME ZONE
        expires_at TIMESTAMP WITH TIME ZONE
        used BOOLEAN
    }
    
    class devices {
        +id SERIAL
        user_id INTEGER
        token_id INTEGER
        credentialpublickey BYTEA
        credentialid BYTEA
        counter INTEGER
        transports TEXT
    }
    
    users "1" -- "0..*" invite_tokens : has
    invite_tokens "0..1" -- "0..1" devices : usedBy
    users "1" -- "0..*" devices : owns
