package com.auth0.samples.authapi.task;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;

import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Data
@NoArgsConstructor
public class Task {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private long id;

	private String description;

	public Task(String description) {
		this.description = description;
	}

}
