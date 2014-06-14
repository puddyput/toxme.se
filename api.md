toxme.se supports a json API via post on https://toxme.se/api

It accepts data in the following format: 
``` {action;
    key;
    ecrypted data;
    base64
    } ```
    
It accepts the following kinds of requests: ```lookup``` and ```announce/update```

Lookup provides record details without asking dns, announce/update is used to join/update your Tox ID after joining.

Lookup: ```{a -> 3; name -> ?}```

Announce/Update: ```{a -> 1; k -> (publickey); e -> (encrypted); r -> (nonce)}```

encrypted: ```{s -> (publickey) + (checksum); n -> (name); l -> <0|1>; b -> (any string); t -> (unixtime)}```

Note: This is clearly not complete
