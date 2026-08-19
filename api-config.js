(function(){
  "use strict";
  // This file contains only the public server address. Never place an API key here.
  window.IP_ASSISTANT_API_ENDPOINT=window.IP_ASSISTANT_API_ENDPOINT||(
    location.protocol==="file:"
      ? "http://localhost:8787/api/assistant"
      : new URL("/api/assistant",location.origin).href
  );
  window.IP_VISITOR_API_ENDPOINT=window.IP_VISITOR_API_ENDPOINT||(
    location.protocol==="file:"
      ? "http://localhost:8787/api/visitors"
      : new URL("/api/visitors",location.origin).href
  );
})();
