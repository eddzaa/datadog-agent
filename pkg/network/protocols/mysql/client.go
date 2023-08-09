// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package mysql TODO comment
package mysql

import (
	"context"
	"database/sql"
	"fmt"
	"net"

	mysqldriver "github.com/go-sql-driver/mysql"
)

// Options exported type should have comment or be unexported
type Options struct {
	ServerAddress string
	Username      string
	Password      string
	DatabaseName  string
	Dialer        *net.Dialer
}

// Client exported type should have comment or be unexported
type Client struct {
	DB     *sql.DB
	dbName string
}

// NewClient exported function should have comment or be unexported
func NewClient(opts Options) (*Client, error) {
	user := opts.Username
	if user == "" {
		user = User
	}

	pass := opts.Password
	if pass == "" {
		pass = Pass
	}
	dbName := opts.DatabaseName
	if dbName == "" {
		dbName = "testdb"
	}

	if opts.Dialer != nil {
		mysqldriver.RegisterDialContext("custom-tcp", func(ctx context.Context, addr string) (net.Conn, error) {
			return opts.Dialer.DialContext(ctx, "tcp", addr)
		})
	}

	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@custom-tcp(%s)/", pass, user, opts.ServerAddress))
	if err != nil {
		return nil, err
	}

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}

	return &Client{
		DB:     db,
		dbName: dbName,
	}, nil
}

// CreateDB exported method should have comment or be unexported
func (c *Client) CreateDB() error {
	_, err := c.DB.Exec("CREATE DATABASE " + c.dbName)
	if err != nil {
		return err
	}

	_, err = c.DB.Exec("USE " + c.dbName)
	return err
}

// DropDB exported method should have comment or be unexported
func (c *Client) DropDB() error {
	_, err := c.DB.Exec("DROP DATABASE " + c.dbName)
	return err
}

// CreateTable exported method should have comment or be unexported
func (c *Client) CreateTable() error {
	_, err := c.DB.Exec("CREATE TABLE cities(id INT PRIMARY KEY AUTO_INCREMENT, name TEXT, population INT);")
	return err
}

// DropTable exported method should have comment or be unexported
func (c *Client) DropTable() error {
	_, err := c.DB.Exec("DROP TABLE cities;")
	return err
}

// AlterTable exported method should have comment or be unexported
func (c *Client) AlterTable() error {
	_, err := c.DB.Exec("ALTER TABLE cities ADD creation_year INT;")
	return err
}

// InsertIntoTable exported method should have comment or be unexported
func (c *Client) InsertIntoTable(name string, population int) error {
	_, err := c.DB.Exec("INSERT INTO cities(name, population) VALUES(?, ?);", name, population)
	return err
}

// DeleteFromTable exported method should have comment or be unexported
func (c *Client) DeleteFromTable(name string) error {
	_, err := c.DB.Exec("DELETE from cities where name=?", name)
	return err
}

// SelectFromTable exported method should have comment or be unexported
func (c *Client) SelectFromTable(name string) (int, error) {
	row := c.DB.QueryRow("select * from cities where name=?;", name)
	if err := row.Err(); err != nil {
		return 0, err
	}
	var city string
	var population int
	var id int
	if err := row.Scan(&id, &city, &population); err != nil {
		return 0, err
	}
	return population, nil
}

// SelectAllFromTable exported method should have comment or be unexported
func (c *Client) SelectAllFromTable() error {
	_, err := c.DB.Query("select * from cities;")
	return err
}

// UpdateTable exported method should have comment or be unexported
func (c *Client) UpdateTable(srcName, newName string, newPopulation int) error {
	_, err := c.DB.Exec("UPDATE cities set name=?, population=? where name=?;", newName, newPopulation, srcName)
	return err
}
