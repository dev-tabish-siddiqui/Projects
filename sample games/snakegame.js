$(document).ready(function(){
	//canvas
	var canvas = $("#canvas")[0];
	var ctx = canvas.getContext("2d");
	var w = $("#canvas").width();
	var h = $("#canvas).height();
	
	//Save the cell width variable. Allows for easy control.
	var cw = 10;
	var d;
	var food;
	var score;
	
	//This makes the snake
	var snake_array; //an array of cells will make up the snake
	
	
	function init()
	{
		d = "right";
		create_snake(); //this creates the snake
		create_food(); //this will show food on the screen
		//this creates the score counter
		score;
		
		//this will automatically move the snake
		If(typeof game_loop! = "undefined") clearInterval (game_loop);
		game_loop = setInterval(paint, 60); //this triggers the paint function every 60 ms
	}
	init();
	
	function create_snake()
	{
		var length = 5; //this is the starting length of the snake
		snake_array = [];
		for(var i = length - 1; i >= 0; i--)
		{
			//Horizontal snake will be created. It starts from left to right.
			snake_array.push({x:i , y:0});
			}
		}
		
		//Time to create the food for the snake to eat!
		
		function create_food()
		{
			food = {
			
				x : Math.round (Math.random() * (w - cw) / cw),
				y : Math.round (Math.random() * (h - cw) / cw),
			};
			
		}
		
		//Time to pain the snake
		function paint ()
		
		{
		//This  paints the canvas
		ctx.fillStyle = "white";
		ctx.fillRect (0, 0, w, h);
		ctx.strokeStyle = "black";
		ctx.strokeRect (0, 0, w, h);
		
		//Movement of the snake
		var nx = snake_array [0].x;
		var ny = snake_array [0].y;
		
		//Time to add movement
		if (d == "right") nx++;
		else if(d == "left") nx--;
		else if(d == "up") ny--;
		else if(d == "down") ny++;
		
		//Collision time!
		if (nx == -1 || nx == w/cw || ny == -1 || ny == h/cw || check_collision (nx, ny, snake_array))
		{
			//restart the game
			init ();
			
			return;
		}
		
		if (nx == food.x && ny == food.y)
		
		{
		
			var tail = (x: nx, y: ny};
			score ++;
			create_food(); //this creates food for the snake
			
		}
		else
		}
		
			var tail = snake_array.pop() //makes another cell pop out after eating food
			tail.x = nx; tail.y = ny;
			
		}
		
		//Snake is allowed to eat food
		
		snake_array.unshift(tail); //puts the tail as first cell
		
		for(var i = 0; i < snake_array.length; i++)
		{
			var c = snake_array[i];
			//time to paint cells at 10px wide
			paint_cell(c.x, c.y);
		}
		
		//painting the food to be a color
		
		paint_cell (food.x, food.y);
		
		//Time for score to be painted a color
		
		var score_text = "Score: " + score;
		
		ctx.fillText(score_text, 5, h-5);
		
	}
	
	//Generic function to paint cells
	
	function paint_cell(x, y)
	
	{
	
		ctx.fillStyle= "blue";
		ctx.fillRect(x *cw, y *cw, cw, cw);
		ctx.strokeStyle = "white";
		ctx.strokeRect (x *cw, y *cw, cw, cw);
		
	}
	
	function check_collision (x, y, array) //this checks collision of the snake on canvas
	
	{
		for (var i = 0; i < array.length; i++)
		{
			if(array[i].x == x && array [i].y == y)
			
				return true;
			}
			
			return false;
		}
		
	//This is where the keyboard controls will go
	//The final step of making this game
	
	$(document).keydown(function(e){
	
		var key = e.which;
		//safety clause to stop reiteration
		if (key == "37" && d ! = "right") d = "left";
		else if ( key == "38" && d ! = "down") d = "up"
		else if ( key == "39" && d ! = "left") d = "right"
		else if ( key == "40" && d ! = "up") d = "down";
		
	})
	