/*
	 Copyright 2018 Yicheng Luo
	 Copyright 2016 Cesanta Software Ltd.

	 Licensed under the Apache License, Version 2.0 (the "License");
	 you may not use this file except in compliance with the License.
	 You may obtain a copy of the License at

			 https://www.apache.org/licenses/LICENSE-2.0

	 Unless required by applicable law or agreed to in writing, software
	 distributed under the License is distributed on an "AS IS" BASIS,
	 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	 See the License for the specific language governing permissions and
	 limitations under the License.
*/

package authn

import (
	"database/sql"
	"fmt"
	"github.com/cesanta/glog"
	_ "github.com/lib/pq"
	"gopkg.in/hlandau/passlib.v1"
	"log"
)

type PostgresAuthConfig struct {
	Url      string `yaml:"url"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	Table    string `yaml:"table"`
}

type PostgresAuthStatus int

const (
	PostgresAuthAllowed PostgresAuthStatus = 0
	PostgresAuthDenied  PostgresAuthStatus = 1
	PostgresAuthNoMatch PostgresAuthStatus = 2
	PostgresAuthError   PostgresAuthStatus = 3
)

type PostgresAuthResponse struct {
	Labels Labels `json:"labels,omitempty"`
}

func checkErr(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func (c *PostgresAuthConfig) Validate() error {
	return nil
}

type PostgresAuth struct {
	cfg *PostgresAuthConfig
	db  *sql.DB
}

func NewPostgresAuth(cfg *PostgresAuthConfig) (*PostgresAuth, error) {
	glog.Infof("Postgresernal authenticator: %s", cfg.Url)
	db, err := sql.Open("postgres", cfg.Url)
	if err != nil {
		return nil, err
	}
	return &PostgresAuth{cfg: cfg, db: db}, nil
}

func (ea *PostgresAuth) Authenticate(user string, password PasswordString) (bool, Labels, error) {
	var db = ea.db

	query := fmt.Sprintf("SELECT %s, %s FROM \"%s\" WHERE username = $1",
		ea.cfg.Username, ea.cfg.Password, ea.cfg.Table)
	row := db.QueryRow(query, user)

	var (
		name    string
		pwdHash string
	)

	err := row.Scan(&name, &pwdHash)

	checkErr(err)

	_, err = passlib.Verify(string(password), pwdHash)
	if err == nil {
		return true, nil, nil
	}
	return false, nil, nil
}

func (sua *PostgresAuth) Stop() {
	sua.db.Close()
}

func (sua *PostgresAuth) Name() string {
	return "postgres"
}
