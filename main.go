package main

import (
	"code.byted.org/axe-amigo/plugins"
)


func main() {
	director := plugins.HireMillionSalaryDirector()
	scheduler, err := director.GetStarter().Start()
	if err != nil {
		panic(err)
	}

	var task *plugins.Task
	for {
		task = scheduler.Next(task)
		plugins.Gao(task, director)
	}
}