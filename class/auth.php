<?php
    namespace auth;
    class json {
        private $auth = [];
        private $loadedAt = NULL;
        private $loadEvery = 60;
    
        private function loadDB() {
            $this->loadedAt = 0;
            
            $json = new \server\JSON();
            $users = $json->select("users");
            foreach($users as $id => $row){
                $this->auth[$row['User-Name']] = $row;
            }
        }
    
        public function getLoginInfo(string $username) {
            if (empty($this->auth) || $this->loadedAt < microtime(true) - $this->loadEvery) {
                $this->loadDB();
            }
            if(isset($this->auth[$username])){
                return $this->auth[$username];
            }
        }
    
    }
