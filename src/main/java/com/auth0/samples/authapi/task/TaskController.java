package com.auth0.samples.authapi.task;

import java.util.List;

import org.springframework.util.Assert;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;

@RestController
@RequestMapping("/tasks")
@Api(tags = "Tasks", description = "Create, Read, Update, Delete")
public class TaskController {

	private TaskRepository taskRepository;

	public TaskController(TaskRepository taskRepository) {
		this.taskRepository = taskRepository;
	}

	@ApiOperation(value = "Create new task")
	@PostMapping
	public void addTask(@RequestBody Task task) {
		taskRepository.save(task);
	}

	@ApiOperation(value = "Get all tasks")
	@GetMapping
	public List<Task> getTasks() {
		return taskRepository.findAll();
	}

	@ApiOperation(value = "Edit task")
	@PutMapping("/{id}")
	public void editTask(@PathVariable long id, @RequestBody Task task) {
		Task existingTask = taskRepository.findOne(id);
		Assert.notNull(existingTask, "Task not found");
		existingTask.setDescription(task.getDescription());
		taskRepository.save(existingTask);
	}

	@ApiOperation(value = "Deletes a task from database")
	@DeleteMapping("/{id}")
	public void deleteTask(@PathVariable long id) {
		taskRepository.delete(id);
	}
}
